use std::env;
use std::io;
use std::io::Write;
use std::process::Command;

fn main() {
    // Use write! as a workaround to avoid https://github.com/rust-lang/rust/issues/46016
    // when piping output to an external program
    let mut stdout = io::stdout();

    let mut output = Command::new("git")
        .args(&["log", "-n1", "--pretty=format:%h", "HEAD"])
        .output()
        .unwrap();
    let mut result = String::from_utf8(output.stdout).unwrap();
    if result.is_empty() {
        result = env::var("BUILDROOT_COMMIT").unwrap_or_default();
        result.truncate(7);
        result = format!("br#{}", result); // add buildroot prefix
    } else if !Command::new("git")
        .args(&["diff", "--quiet"])
        .status()
        .expect("failed to execute process")
        .success()
    {
        result += "-dirty";
    }
    _ = write!(&mut stdout, "cargo:rustc-env=GIT_HASH={}\n", result);

    output = Command::new("git")
        .args(&["log", "-n1", "--pretty=format:%cd", "--date=short", "HEAD"])
        .output()
        .unwrap();
    result = String::from_utf8(output.stdout).unwrap().replace("-", "");
    if result.is_empty() {
        result = env::var("AA_PROXY_COMMIT").unwrap_or_default();
        result.truncate(7);
    }
    _ = write!(&mut stdout, "cargo:rustc-env=GIT_DATE={}\n", result);

    output = Command::new("date")
        .args(&["+%Y%m%d_%H%M%S"])
        .output()
        .unwrap();
    result = String::from_utf8(output.stdout).unwrap();
    _ = write!(&mut stdout, "cargo:rustc-env=BUILD_DATE={}\n", result);

    // creating protobuf
    protobuf_codegen::Codegen::new()
        // Use `protoc` parser, optional.
        .protoc()
        // Use `protoc-bin-vendored` bundled protoc command, optional.
        .protoc_path(&protoc_bin_vendored::protoc_bin_path().unwrap())
        // All inputs and imports from the inputs must reside in `includes` directories.
        .includes(&["src/protos"])
        // Inputs must reside in some of include paths.
        .input("src/protos/WifiStartRequest.proto")
        .input("src/protos/WifiInfoResponse.proto")
        .input("src/protos/protos.proto")
        .input("src/protos/ev.proto")
        // Specify output directory relative to Cargo output directory.
        .cargo_out_dir("protos")
        .run_from_script();

    #[cfg(feature = "cvi")]
    build_cvi();
}

/// Builds the C layer for the Sophgo SG2000/SG2002 hardware codec (`cvi` feature) and links the
/// vendor libraries.
///
/// Environment:
/// - `CVI_MPI_INC`: directory with the cvi_mpi headers (`cvi_sys.h`, `cvi_venc.h`, `cvi_vdec.h`
///   and the `linux/` subdirectory). In a Buildroot build: `$(STAGING_DIR)/usr/include/cvi_mpi`.
/// - `CVI_MPI_LIB`: directory with `libsys`, `libvenc`, `libvdec` (and `libatomic`) for the target.
///   In a Buildroot build: `$(STAGING_DIR)/usr/lib`.
///
/// - `CVI_MPI_LINK`: `dylib` (default) or `static`.
///
/// Note: musl targets link statically by default (crt-static), which cannot use the shared
/// libraries: build with `RUSTFLAGS="-C target-feature=-crt-static"`, or set `CVI_MPI_LINK=static`.
#[cfg(feature = "cvi")]
fn build_cvi() {
    println!("cargo:rerun-if-changed=src/cvi/aap_cvi.c");
    println!("cargo:rerun-if-changed=src/cvi/aap_cvi.h");
    println!("cargo:rerun-if-env-changed=CVI_MPI_INC");
    println!("cargo:rerun-if-env-changed=CVI_MPI_LIB");

    let inc = env::var("CVI_MPI_INC").unwrap_or_else(|_| {
        panic!(
            "the `cvi` feature needs CVI_MPI_INC (directory with the cvi_mpi headers: cvi_sys.h, \
             cvi_venc.h, cvi_vdec.h, linux/cvi_*.h)"
        )
    });
    let lib = env::var("CVI_MPI_LIB").unwrap_or_else(|_| {
        panic!(
            "the `cvi` feature needs CVI_MPI_LIB (directory with libsys/libvenc/libvdec for the target)"
        )
    });

    cc::Build::new()
        .file("src/cvi/aap_cvi.c")
        .include("src/cvi")
        .include(&inc)
        // SG2000/SG2002 are CV181x (the vendor header defaults to CV180x)
        .define("__CV181X__", None)
        .flag_if_supported("-std=gnu11")
        .warnings(true)
        .compile("aap_cvi");

    // `dylib` (default) or `static` (uses libsys.a/libvenc.a/libvdec.a, handy for crt-static musl)
    println!("cargo:rerun-if-env-changed=CVI_MPI_LINK");
    let kind = match env::var("CVI_MPI_LINK").as_deref() {
        Ok("static") => "static",
        _ => "dylib",
    };

    println!("cargo:rustc-link-search=native={lib}");
    // libvenc/libvdec depend on libsys; libsys needs libatomic (atomic_bool on RISC-V)
    println!("cargo:rustc-link-lib={kind}=venc");
    println!("cargo:rustc-link-lib={kind}=vdec");
    println!("cargo:rustc-link-lib={kind}=sys");
    println!("cargo:rustc-link-lib={kind}=atomic");
}
