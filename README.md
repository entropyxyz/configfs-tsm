# configfs-tsm

This can generate quotes for remote attestation on confidential computing platforms using Linux's
[configfs-tsm](https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm) filesystem
interface.

This is designed for and tested with Intel TDX, but since the `configfs-tsm` is a platform-agnostic
interface, this could potentially work with other platforms such as Intel SGX, or AMD SEV.

This crate has no dependencies and generates quotes only by reading and writing local files.

Warning: This crate is in early stages of development and has not been audited
