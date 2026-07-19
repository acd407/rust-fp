use std::ffi::CStr;
use std::sync::mpsc::channel;
use std::time::Duration;

use pam::constants::PamResultCode::{PAM_AUTH_ERR, PAM_SUCCESS};
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF};
use pam::conv::Conv;
use pam::items::{AuthTok, RUser};
use pam::module::{PamHandle, PamHooks};
use postcard::from_bytes;
use pwd::Passwd;
use zbus::blocking::Connection;

use rust_fp::fingerprint_driver::{MatchOutput, MatchedOutput};
use rust_fp_common::get_templates::get_templates_for;
use rust_fp_common::rust_fp_dbus::RustFpProxyBlocking;
use rust_fp_common::set_templates::set_templates_for;

fn syslog_info(msg: &str) {
    let c_msg = std::ffi::CString::new(msg).unwrap();
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_INFO,
            c"%s".as_ptr(),
            c_msg.as_ptr(),
        );
    }
}

struct RustFpPam;
pam::pam_hooks!(RustFpPam);

fn init_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()));
        let full = format!("PANIC: {msg} at {location:?}");
        let c_msg = std::ffi::CString::new(full).unwrap();
        unsafe {
            libc::syslog(
                libc::LOG_AUTHPRIV | libc::LOG_CRIT,
                c"%s".as_ptr(),
                c_msg.as_ptr(),
            );
        }
    }));
}

fn do_fingerprint_match(
    px: &RustFpProxyBlocking<'_>,
    templates: &mut std::collections::HashMap<String, Vec<u8>>,
    home_dir: &str,
) -> PamResultCode {
    let templates_vec = templates.iter().collect::<Vec<_>>();
    let max_attempts = 5;
    for attempt in 0..max_attempts {
        let output: MatchOutput = match from_bytes(
            &px.match_templates(
                templates_vec
                    .iter()
                    .map::<Vec<u8>, _>(|(_k, v)| v.to_vec())
                    .collect(),
            )
            .unwrap(),
        ) {
            Ok(o) => o,
            Err(_) => {
                syslog_info("Could not decode match output");
                return PAM_AUTH_ERR;
            }
        };
        match output {
            MatchOutput::Match(MatchedOutput {
                index,
                updated_template,
            }) => {
                let matched_label = templates_vec[index].0;
                if let Some(template) = updated_template {
                    templates.insert(matched_label.to_owned(), template);
                    let _ = set_templates_for(home_dir, templates);
                }
                return PAM_SUCCESS;
            }
            MatchOutput::NoMatch(_error) => {
                let remaining = max_attempts - attempt - 1;
                if remaining > 0 {
                    syslog_info(&format!("No match. {remaining} attempts remaining."));
                }
            }
        }
    }
    PAM_AUTH_ERR
}

impl PamHooks for RustFpPam {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        init_panic_hook();
        let grosshack = args.iter().any(|a| a.to_bytes() == b"grosshack");
        syslog_info(&format!(
            "sm_authenticate called, PID={}, grosshack={grosshack}",
            std::process::id()
        ));

        let pam_user = match pamh.get_item::<RUser>() {
            Ok(Some(ruser)) => ruser.to_string_lossy().into_owned(),
            _ => match pamh.get_user(None) {
                Ok(u) => u,
                Err(_) => {
                    syslog_info("get_user failed");
                    return PAM_AUTH_ERR;
                }
            },
        };
        syslog_info(&format!("pam_user={pam_user}"));

        let home_dir = match Passwd::from_name(&pam_user) {
            Ok(Some(entry)) => entry.dir,
            _ => {
                syslog_info(&format!("Passwd::from_name failed for {pam_user}"));
                return PAM_AUTH_ERR;
            }
        };
        syslog_info(&format!("home_dir={home_dir}"));

        let templates = get_templates_for(&home_dir).unwrap_or_default();

        // Start fingerprint in background if templates exist
        let (fp_tx, fp_rx) = channel();
        if !templates.is_empty() {
            let home_dir_fp = home_dir.clone();
            let mut templates_fp = templates.clone();
            std::thread::Builder::new()
                .name("fp-match".into())
                .spawn(move || {
                    let (dbus_tx, dbus_rx) = channel();
                    std::thread::Builder::new()
                        .name("dbus-conn".into())
                        .spawn(move || {
                            let conn = Connection::system();
                            let _ = dbus_tx.send(conn);
                        })
                        .ok();
                    let connection = match dbus_rx.recv_timeout(Duration::from_secs(3)) {
                        Ok(Ok(c)) => c,
                        _ => {
                            let _ = fp_tx.send(PAM_AUTH_ERR);
                            return;
                        }
                    };
                    let proxy = match RustFpProxyBlocking::new(&connection) {
                        Ok(p) => p,
                        Err(_) => {
                            let _ = fp_tx.send(PAM_AUTH_ERR);
                            return;
                        }
                    };
                    let result = do_fingerprint_match(&proxy, &mut templates_fp, &home_dir_fp);
                    let _ = fp_tx.send(result);
                })
                .ok();
        }

        if grosshack {
            let conv = match pamh.get_item::<Conv>() {
                Ok(Some(conv)) => conv,
                _ => {
                    syslog_info("no PAM conv available");
                    if !templates.is_empty() {
                        if let Ok(PAM_SUCCESS) = fp_rx.recv_timeout(Duration::from_secs(30)) {
                            return PAM_SUCCESS;
                        }
                    }
                    return PAM_AUTH_ERR;
                }
            };

            match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                Ok(Some(resp)) => {
                    let password = resp.to_bytes();
                    if !password.is_empty() {
                        let cstr = resp.to_owned();
                        let _ = pamh.set_item_str::<AuthTok>(AuthTok(&cstr));
                        syslog_info("password entered, delegating to pam_unix");
                        return PAM_AUTH_ERR;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    syslog_info(&format!("conv prompt failed: {e:?}"));
                }
            }

            syslog_info("empty password, trying fingerprint");
            if !templates.is_empty() {
                match fp_rx.recv_timeout(Duration::from_secs(30)) {
                    Ok(PAM_SUCCESS) => {
                        syslog_info("fingerprint matched");
                        return PAM_SUCCESS;
                    }
                    Ok(PAM_AUTH_ERR) => {
                        syslog_info("fingerprint no match");
                    }
                    Ok(other) => {
                        syslog_info(&format!("fingerprint error: {other:?}"));
                    }
                    Err(_) => {
                        syslog_info("fingerprint timeout");
                    }
                }
            }
            PAM_AUTH_ERR
        } else {
            syslog_info("pure fingerprint mode");
            if !templates.is_empty() {
                match fp_rx.recv_timeout(Duration::from_secs(30)) {
                    Ok(PAM_SUCCESS) => {
                        syslog_info("fingerprint matched");
                        return PAM_SUCCESS;
                    }
                    Ok(PAM_AUTH_ERR) => {
                        syslog_info("fingerprint no match");
                    }
                    Ok(other) => {
                        syslog_info(&format!("fingerprint error: {other:?}"));
                    }
                    Err(_) => {
                        syslog_info("fingerprint timeout");
                    }
                }
            }
            PAM_AUTH_ERR
        }
    }
}
