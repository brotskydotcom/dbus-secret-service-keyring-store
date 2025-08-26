/*!

# dbus-secret-service credential store for keyring

This module implements a credential store for the
[keyring](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring)
that uses the secret service as its back end via the
[dbus-secret-service crate](https://crates.io/crates/dbus-secret-service).

## Attributes

Items in the secret-service are organized into collections,
and are identified by an arbitrary collection of attributes.

New items are created in the default collection,
unless a target other than `default` is
specified for the entry. In that case, the item
will be created in a collection labeled by the specified target;
that collection will be created if necessary.

This implementation controls the following attributes:

- `target` (optional & taken from modifier `target` in the entry creation call)
- `service` (required & taken from entry creation call)
- `username` (required & taken from entry creation call's `user` parameter)

In addition, when creating a new credential, this implementation assigns
the created entry a label property (for use in Secret Service UI). If the
modifier `label` is set in the entry creation call, that value is used
as the label. Otherwise, the label is set to the Rust-formatted string:
`keyring:{user}@{service}`.

Client code is allowed to retrieve and to set all attributes _except_ the
three that are controlled by this implementation. The label is accessible
through credential-level calls, but not entry-level calls.

## Ambiguity

Existing items are always searched for at the service level, which means all
collections are searched. The search attributes used are `service` (set from the
entry service), and `username` (set from the entry user). In addition, if a
`target` modifier was specified in the creation call of an entry, the `target`
attribute is also used in the search for that entry: this allows items with the
same service and user in different collections to be distinguished.

Note that existing items created by 3rd party applications may have additional
attributes; such items will be found when searching for items with the same
service and user.

## Headless usage

If you must use the secret-service on a headless linux box,
be aware that there are known issues with getting
dbus and secret-service and the gnome keyring
to work properly in headless environments.
For a quick workaround, look at how this project's
[CI workflow](https://github.com/hwchen/keyring-rs/blob/master/.github/workflows/ci.yaml)
starts the Gnome keyring unlocked with a known password;
a similar solution is also documented in the
[Python Keyring docs](https://pypi.org/project/keyring/)
(search for "Using Keyring on headless Linux systems").
The following `bash` function may be helpful:

```shell
function unlock-keyring ()
{
    read -rsp "Password: " pass
    echo -n "$pass" | gnome-keyring-daemon --unlock
    unset pass
}
```

For an excellent treatment of all the headless dbus issues, see
[this answer on ServerFault](https://serverfault.com/a/906224/79617).

## Usage on Windows Subsystem for Linux

As noted in
[this issue on GitHub](https://github.com/open-source-cooperative/keyring-rs/issues/133),
there is no "default" collection defined under WSL.  So
this crate will not work on WSL unless you specify a non-`default` target
modifier on every specifier.

 */

pub mod cred;
pub mod errors;
mod service;
pub mod store;
pub use store::Store;
#[cfg(test)]
mod tests;
