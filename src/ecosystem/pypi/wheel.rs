//! Which platforms a wheel installs on, from the platform tags in its file name (PEP 427):
//! `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`, the platform tag set
//! joined by `.`, such as `manylinux2014_x86_64.manylinux_2_17_x86_64`.

use crate::lockfile::Target;

/// Whether `filename` is a wheel that installs on `target`. A file that is not a wheel, or
/// whose name has no platform tag, is not one.
pub fn installs_on(filename: &str, target: &Target) -> bool {
    let Some(stem) = filename.strip_suffix(".whl") else {
        return false;
    };
    let Some((_, platforms)) = stem.rsplit_once('-') else {
        return false;
    };
    platforms.split('.').any(|tag| tag_installs_on(tag, target))
}

/// Whether one platform tag, such as `musllinux_1_2_aarch64`, installs on `target`.
fn tag_installs_on(tag: &str, target: &Target) -> bool {
    if tag == "any" {
        return true;
    }
    let arch = |names: &[&str]| names.iter().any(|name| tag.ends_with(&format!("_{name}")));
    match target.os.as_str() {
        "linux" => {
            let family = match target.libc.as_deref() {
                Some("musl") => tag.starts_with("musllinux_"),
                _ => tag.starts_with("manylinux") || tag.starts_with("linux_"),
            };
            family
                && match target.cpu.as_str() {
                    "x64" => arch(&["x86_64"]),
                    "arm64" => arch(&["aarch64"]),
                    "ia32" => arch(&["i686"]),
                    "arm" => arch(&["armv7l"]),
                    other => arch(&[other]),
                }
        }
        "darwin" => {
            tag.starts_with("macosx_")
                && match target.cpu.as_str() {
                    "x64" => arch(&["x86_64", "intel", "universal", "universal2"]),
                    "arm64" => arch(&["arm64", "universal2"]),
                    other => arch(&[other]),
                }
        }
        "win32" => matches!(
            (target.cpu.as_str(), tag),
            ("x64", "win_amd64") | ("ia32", "win32") | ("arm64", "win_arm64")
        ),
        _ => false,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn target(value: &str) -> Target {
        Target::parse(value).expect("a target")
    }

    /// Each wheel installs on the platforms its tags name, and on every platform for `any`.
    #[test]
    fn a_wheel_installs_where_its_platform_tags_say() {
        let wheels = [
            ("six-1.17.0-py2.py3-none-any.whl", "every"),
            (
                "numpy-2.5.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
                "linux-x64",
            ),
            ("numpy-2.5.3-cp313-cp313-linux_x86_64.whl", "linux-x64"),
            (
                "numpy-2.5.3-cp313-cp313-manylinux_2_28_aarch64.whl",
                "linux-arm64",
            ),
            (
                "numpy-2.5.3-cp313-cp313-manylinux_2_28_i686.whl",
                "linux-ia32",
            ),
            ("numpy-2.5.3-cp313-cp313-linux_armv7l.whl", "linux-arm"),
            (
                "numpy-2.5.3-cp313-cp313-manylinux_2_28_s390x.whl",
                "linux-s390x",
            ),
            (
                "numpy-2.5.3-cp313-cp313-musllinux_1_2_x86_64.whl",
                "linux-x64-musl",
            ),
            (
                "numpy-2.5.3-cp313-cp313-macosx_14_0_arm64.whl",
                "darwin-arm64",
            ),
            (
                "numpy-2.5.3-cp313-cp313-macosx_10_13_x86_64.whl",
                "darwin-x64",
            ),
            (
                "numpy-2.5.3-cp313-cp313-macosx_10_9_ppc64.whl",
                "darwin-ppc64",
            ),
            ("numpy-2.5.3-cp313-cp313-win_amd64.whl", "win32-x64"),
            ("numpy-2.5.3-cp313-cp313-win32.whl", "win32-ia32"),
            ("numpy-2.5.3-cp313-cp313-win_arm64.whl", "win32-arm64"),
        ];
        let targets = [
            "linux-x64",
            "linux-arm64",
            "linux-ia32",
            "linux-arm",
            "linux-s390x",
            "linux-x64-musl",
            "darwin-arm64",
            "darwin-x64",
            "darwin-ppc64",
            "win32-x64",
            "win32-ia32",
            "win32-arm64",
            "freebsd-x64",
        ];
        for (wheel, on) in wheels {
            for t in targets {
                let expected = on == "every" || on == t;
                assert_eq!(installs_on(wheel, &target(t)), expected, "{wheel} on {t}");
            }
        }
    }

    /// A universal2 macOS wheel installs on both Mac architectures, and an older
    /// universal or intel one on Intel Macs.
    #[test]
    fn a_universal_mac_wheel_installs_on_each_architecture_it_names() {
        let universal2 = "pillow-12.3.0-cp313-cp313-macosx_11_0_universal2.whl";
        assert!(installs_on(universal2, &target("darwin-arm64")));
        assert!(installs_on(universal2, &target("darwin-x64")));
        for older in ["macosx_10_6_intel", "macosx_10_6_universal"] {
            let wheel = format!("x-1.0-cp27-cp27m-{older}.whl");
            assert!(installs_on(&wheel, &target("darwin-x64")), "{older}");
            assert!(!installs_on(&wheel, &target("darwin-arm64")), "{older}");
        }
    }

    /// An sdist, and a name with no platform tag, install nowhere as a wheel.
    #[test]
    fn a_file_that_is_not_a_tagged_wheel_is_not_one() {
        assert!(!installs_on("six-1.17.0.tar.gz", &target("linux-x64")));
        assert!(!installs_on("weird.whl", &target("linux-x64")));
    }
}
