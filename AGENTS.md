# TYPHOON protocol development

Below several instructions for AI agents are stated, that are highly recommended during TYPHOON project development.

## General rules

- Before making any changes, please, come up with a short summary of what you are about to do, present it to me and ask for my confirmation.

## Core library

Always compare your implementation to [README.md](./README.md) file, the code should always be compliant to the behavior defined in the file.

### Code

- The core library resides in `./typhoon` directory and is written in `rust`.
- The concurrent code should be implemented using asynchronous feature and runtime-agnostic primitives, defined in `utils/sync.rs`.

### Formatting

- Implementation should be clean, short, correct and efficient; additional effort should be put into making sure that as few data is copied at runtime as possible.
- No unnecessary unused functions should be generated, no comments describing generation process should be outputted.
- Comments should be put in a form of documentation strings, one per function, trait, struct and file.
