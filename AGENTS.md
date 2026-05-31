# TYPHOON protocol development

Below several instructions for AI agents are stated, that are highly recommended during TYPHOON project development.

## General rules

- Before making any changes, please, come up with a short summary of what you are about to do, present it to me and ask for my confirmation.
- Do not jump to conclusions or invent things that will considerably impact system design, but rather include the important questions into your plan (and don't hesitate to ask again if you still have questions even after I answer).
- After making any changes, please, don't forget to update related documentation and tests and then run the unit tests.

## Core library

Always compare your implementation to [README.md](./README.md) file, the code should always be compliant to the behavior defined in the file.

### Code

The core library resides in `./typhoon` directory and is written in `rust` (also there are modules in `evaluation/protocols/typhoon` and `evaluation/protocols/wireguard_daita/machines-printer`).
The evaluation library used for `TYPHOON` protocol research, testing and comparison with other protocols resides in `./evaluation` directory and is written in `python`.
There is a `go` module in `evaluation/protocols/wireguard_daita/wg-daita` as well as several environment files, `Dockerfile`s and shell scripts scattered around the project.

#### Rust

- Implementation should be clean, short, correct and efficient.
- No unnecessary unused functions, constants, variables or traits should be generated, no comments describing generation process should be outputted.
- No need to preserve any backward compatibility features or make any migration code unless it is specifically mentioned otherwise.
- Comments should be put in a form of documentation strings, one per function, trait, struct and file.
- Wherever a generalization is possible, using macros should be preferred over repetitive boilerplate code.
- The concurrent code should be implemented using asynchronous feature and runtime-agnostic primitives, defined in `utils/sync.rs`.
- Use constants instead of magic numbers whenever possible.
- Take care of memory management: avoid copies as much as possible, data should almost be never copied, and instead be represented as views on pre-allocated pooled `ByteBuffer`s.
- Also please, avoid any other object runtime allocation: cloning, copying, but most importantly heap-based types, like `Box`es or `Vec`s, these should never used if possible.
- Short functions should be inlined.
- No internal types should be exposed, exceptions include: `ByteBuffer`s, `Socket`s, `Settings`, `Certificate`s and configuration objects.
- As a general rule, in every case, where an object is constructed, that is meant to *intercept*, *send* or *receive* some data flow, the data flow (including all the queues, background tasks, etc.) should be constructed in advance, ideally - in the same construction method as the object itself, and then returned as a tuple.
- In the concurrent environment, excessive locking (even the critical sections) should be avoided, as the protocol is designed for transferring large data payloads; non-locking types (atomics or the ones from `crossbeam` library) should be preferred over `RwLock`s, while `RwLock`s should be preferred over `Mutex`es.
- Template types should be preferred over dynamically-sized types (`dyn`-prefixed), for reducing heap allocations.
- Prefer direct imports over fully-qualified ones: `use foo::bar::Type; Type...` instead of just `foo::bar::Type`, placing them at the top of the file (not inline).
- Prefer simpler synchronization primitives to channels: `Arc`/`Weak` pairs + function invocations for data transferring, lock-free dequeues for async event processing, etc.
- When gating code, prefer applying `#[cfg(...)]` to imports, types, fields and functions, but not to the code (inside of a function).
- All the test-related code (marked with `#[cfg(test)]`) should reside in `typhoon/tests` directory, the directory structure should match the `typhoon/src` source code structure, the test-related code should not be placed into sources.
- Long lines should not be broken, for the other linting requirements please see `typhoon/.rustfmt.toml` (`fmt` tool) and `typhoon/.clippy.toml` (`clippy` tool).

#### Python

- The concurrent code should be implemented using asynchronous feature.
- No unnecessary unused functions, constants, variables or traits should be generated, no comments describing generation process should be outputted.
- No need to preserve any backward compatibility features or make any migration code unless it is specifically mentioned otherwise.
- Use constants instead of magic numbers whenever possible.
- When calling one `python` file from another prefer importing to all other methods.
- When using imports (including standard library imports) always prefer putting import statements to the top of the file, not inline, and also prefer `from ... import ...` syntax to import individual types, classes, functions, constants (not modules).
- Use type hints whenever possible.
- Long lines should not be broken, for the other linting requirements please see `evaluation/pyproject.toml` (`ruff` tool).

#### Other languages

- For `go` code, standard rules should be applied (linted with `staticcheck` tool).
- For `Dockerfile`s, standard rules should be applied (linted with `hadolint` tool, configuration can be found in `evaluation/.hadolint.yaml`).
- For shell scripts, standard rules should be applied (linted with `shellcheck` tool).
- For markdown files, standard rules should be applied (linted with `markdownlint` tool).
- Everywhere (wherever the linting rules don't **specifically** enforce otherwise) long lines should be preferred over broken lines.
- Avoid generated file embedding (configuration, environment, etc.), and prefer separate template files instead.

### Testing

All the tests and builds should be run with two different sets of features:

- `fast_software`, `server`, `client`, `tokio` (the default mode)
- `full_hardware`, `server` `client`, `async-std`
