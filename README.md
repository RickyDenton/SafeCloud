# SafeCloud Service
A simple yet secure cloud-based storage service

## Documentation
The project report and the full-size version of all its embedded images can be found in the `docs` directory

## Build and Compile
The service has been implemented in the C++14 language using the [cmake](https://cmake.org/) toolchain based on the [ninja](https://ninja-build.org/) build system and the [clang](https://clang.llvm.org/), with both the *SafeCloud Client* and *SafeCloud Server* applications that have been developed two versions:
- A *Debug Version* intended for development and testing purposes, which is compiled by defining the *DEBUG_MODE* project-wide symbol at compile time (*-DDEBUG_MODE* option), in which most of the applications’ intermediate results, secret quantities included, as well as the source file and line number at which errors occurs at, are logged to *stdout* so to allow for an easier troubleshooting.
- A *Release Version* intended to be deployed on the *SafeCloud Server* system(s) and to be distributed to the service’s users, in which only the applications’ main results are reported and the underlying reason of *login errors* is concealed in the *SafeCloud Client* so to preclude malicious users any insights in attempting to impersonate other authenticated users.

## Running the service
1. *(optional)* Compile and build the project in *debug* and/or *release* mode
2. Start a *SafeCloud Server* instance, whose binary can be found in the `release/server/` folder and accepts the following command-line parameters:
   - "-p [PORT]" → The port on the host OS to bind on.
3. Start any number of *SafeCloud Client* instances, whose binary is found in the `release/client/` folder and accepts the following command-line parameters:
   - "-a [IPv4]" → The IP address of the *SafeCloud Server* instance to connect to
   - "-p [PORT]" → The port of the *SafeCloud Server* instance to connect to
4. *Login* in the *SafeCloud Client* instance(s) by using any of the following pre-registered users' credentials:

   | *username*  | *password*    |
   | ----------- | ------------- |
   | alice       | alicepassword |
   | bob         | bobpassword   |
   | carol       | carolpassword |

5. Once a *SafeCloud Client* has successfully connected to its designated *SafeCloud Server* instance, the list of available application commands can be viewed by entering the `help` command .

6. The two applications can be shut down by:
   - Sending them an interrupt signal *(CTRL+C)*.
   - *(SafeCloud Client only)* logging out from the *SafeCloud Server* instance via the `logout` command.
