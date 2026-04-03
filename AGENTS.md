# TYPHOON protocol development

Below several instructions for AI agents are stated, that are highly recommended during TYPHOON project development.

## General rules

- Before making any changes, please, come up with a short summary of what you are about to do, present it to me and ask for my confirmation.
- After making any changes, please, don't forget to update related documentation and tests and then run the unit tests.

## Core library

Always compare your implementation to [README.md](./README.md) file, the code should always be compliant to the behavior defined in the file.

### Code

- The core library resides in `./typhoon` directory and is written in `rust`.
- The concurrent code should be implemented using asynchronous feature and runtime-agnostic primitives, defined in `utils/sync.rs`.
- Use constants instead of magic numbers whenever possible.
- Take care of memory management: avoid copies as much as possible, data should almost be never copied, and instead be represented as views on pre-allocated pooled `ByteBuffer`s.
- Also please, avoid any other object runtime allocation: cloning, copying, but most importantly heap-based types, like `Box`es or `Vec`s, these should never used if possible.
- Short functions should be inlined.
- No internal types should be exposed, exceptions include: `ByteBuffer`s, `Socket`s, `Settings`, `Certificate`s and configuration objects.
- As a general rule, in every case, where an object is constructed, that is meant to *intercept*, *send* or *receive* some data flow, the data flow (including all the queues, background tasks, etc.) should be constructed in advance, ideally - in the same construction method as the object itself, and then returned as a tuple.
- In the concurrent environment, excessive locking (even the critical sections) should be avoided, as the protocol is designed for transferring large data payloads; non-locking types (atomics or the ones from `crossbeam` library) should be preferred over `RwLock`s, while `RwLock`s should be preferred over `Mutex`es.
- Template types should be preferred over dynamically-sized types (`dyn`-prefixed), for reducing heap allocations.
- Prefer direct imports over fully-qualified ones: `use foo::bar::Type; Type...` instead of just `foo::bar::Type`.
- Prefer simpler synchronization primitives to channels: `Arc`/`Weak` pairs + function invocations for data transferring, lock-free dequeues for async event processing, etc.

### Formatting

- Implementation should be clean, short, correct and efficient.
- No unnecessary unused functions, constants, variables or traits should be generated, no comments describing generation process should be outputted.
- Comments should be put in a form of documentation strings, one per function, trait, struct and file.

### Testing

All the tests and builds should be run with two different sets of features:

- `fast_software`, `server`, `client`, `tokio` (the default mode)
- `full_hardware`, `server` `client`, `async-std`
