# `rust-fp`
A better fingerprint library than `libfprint`

## Why
- `libfprint` does not support Chromebook fingerprint readers
- `libfprint` seems to not support fingerprint readers with their own built-in matching
- `libfprint` is written in C, not Rust
- `libfprint` is hard to use

## Goals
- Support enrolling fingerprints through a GUI and CLI
- Support authenticating with fingerprints with PAM
- Be easy to develop new drivers, even if you just have 1 test device and it's the same device that you're using to code
- Support Chromebook fingerprint sensors
- Be modular and easy to use in non-Linux environments (such as RedoxOS)
- Be easy to set up a development environment to build and edit the code
- Provide high quality auto-complete in code editors
- Be as close to 100% Rust as possible with minimal non-Rust dependencies

## Status
### Drivers
Currently, `rust-fp` supports Chromebook fingerprint readers. Other people can add drivers for their own fp sensors.

### Integration with desktop environments
Desktop Environment | Status      | Comments
--------------------|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
KDE Plasma          | Working     | Works by configuring the rust-fp PAM module
GNOME               | Not working | Just replacing libfprint PAM module with rust-fp PAM module doesn't work. See https://github.com/ChocolateLoverRaj/rust-fp/issues/3
COSMIC              | Planned     | Since COSMIC is written in Rust 🦀, it shouldn't be too hard to add nice support for rust-fp unlock. Maybe even skip PAM entirely and directly add rust-fp integration to COSMIC. Once COSMIC is officially released and I switch to COSMIC, I'll work on this.

If you get this working with another DE, create a PR adding it to the table.

## Installation
### NixOS
In your `flake.nix`, add the following input:
```nix
rust-fp.url = "github:ChocolateLoverRaj/rust-fp";
```
Then destructure the input:
```nix
{ self, nixpkgs, rust-fp, ... }@inputs:
```
Then use the default module:
```nix
rust-fp.nixosModules.default
```
[Example of using `rust-fp` on Jinlon](https://github.com/ChocolateLoverRaj/nixos-system-config/blob/main/flake.nix)

### Manually, in normal mutable Linux distros
#### Get the code
```sh
git clone https://github.com/ChocolateLoverRaj/rust-fp
```

#### Install [Rust 🦀](https://www.rust-lang.org/)

#### Install the build dependency package
##### With Nix
Even if you're not on NixOS, you can probably install [`Nix`](https://nixos.org/download/) on any distro and just get everything you need with `nix develop`.
##### Without Nix
Or you can find the packages that your distribution provides and install them with your other package manager. You probably need `pam`, and maybe `clang`.

#### Build everything
Run
```sh
cargo b --release
```
That should build everything. If you are testing changes to the code, then just run `cargo b` to build in debug mode.

#### Install D-Bus config
```sh
sudo cp dbus-interface/org.rust_fp.RustFp.conf /usr/share/dbus-1/system.d
```

#### Install `rust-fp-dbus-interface`
```sh
sudo cp target/release/rust-fp-dbus-interface /usr/bin
```

#### Create the systemd service
```bash
sudo cp rust-fp-dbus-interface.service /etc/systemd/system
```
You can start it with
```bash
sudo systemctl enable --now rust-fp-dbus-interface
```

#### Configure PAM
Copy the PAM module to the location where PAM modules belong
```bash
sudo cp target/release/librust_fp_pam_module.so /lib64/security
```
Depending on the distro, the folder might be `/lib` or `/lib64`. On Fedora it's `/lib64`.

Create / modify the PAM config file (e.g. `/etc/pam.d/sudo`) with one of the following configurations:

**Pure fingerprint mode** — no password prompt:
```
auth    sufficient    librust_fp_pam_module.so
```

**Grosshack mode** — password prompt with fingerprint fallback (empty password triggers fingerprint):
```
auth    sufficient    librust_fp_pam_module.so grosshack
auth    sufficient    pam_unix.so try_first_pass nullok
```

#### Install the CLI
```bash
sudo cp target/release/rust-fp /usr/local/bin
```

## Usage
Enroll fingerprints with the `rust-fp` CLI. Depending on your Chromebook, there is a maximum number of templates that can be loaded onto the fingerprint sensor at a time — probably 5. Run `rust-fp add <name>` to enroll a fingerprint.

Lock the screen and you should be able to unlock:
- **Pure fingerprint mode**: fingerprint only
- **Grosshack mode**: enter password, or press Enter with an empty password to use fingerprint

## Troubleshooting
- See [the list of known issues](https://github.com/ChocolateLoverRaj/rust-fp/labels/bug).
- Try restart the systemd service
- Try clearing stored templates with `rust-fp clear` and then enrolling new ones.
