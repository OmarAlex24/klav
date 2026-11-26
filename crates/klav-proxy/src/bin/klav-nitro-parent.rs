//! `klav-nitro-parent` (ADR 0051 §1, §5.3): the whole program is
//! [`klav_proxy::parent::main`].

fn main() -> std::process::ExitCode {
    klav_proxy::parent::main()
}
