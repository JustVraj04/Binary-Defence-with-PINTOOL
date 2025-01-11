# Binary Defence with PINTOOL

This project was created as part of My Coursework For System Security and Binary Code Analysis. The project delved into below details.

- Developed a dynamic defense mechanism against arbitrary write attacks targeting the Global Offset Table (GOT) using
the PIN dynamic binary instrumentation framework, enabling runtime monitoring without source code access.
- Implemented a runtime protection system that detects suspicious memory write instructions attempting to overwrite
GOT entries and traces the function call history to validate legitimacy, raising alarms when unauthorized writes are
detected.
- Adapted the solution to handle Position Independent Executables (PIE), supporting dynamic address calculation and
protection in ASLR environments.

The full project is in Part-3. Find the README.md file in part 3 to help you install and how to use the defense tool.
