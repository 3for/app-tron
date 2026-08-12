# app-tron

[![Build and run functional tests](https://github.com/LedgerHQ/app-tron/actions/workflows/build_and_functional_tests.yml/badge.svg?branch=develop)](https://github.com/LedgerHQ/app-tron/actions/workflows/build_and_functional_tests.yml)

Tron wallet application for Ledger Nano S Plus, Nano X, Flex, Stax, Apex P.

# Quick start guide

## With VSCode

You can quickly setup a convenient environment to build and test your application by using
[Ledger's VSCode developer tools extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools)
which leverages the [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools)
docker image.

It will allow you, whether you are developing on macOS, Windows or Linux,
to quickly **build** your apps, **test** them on **Speculos** and **load** them on any supported device.

- Install and run [Docker](https://www.docker.com/products/docker-desktop/).
- Make sure you have an X11 server running:
  - On Ubuntu Linux, it should be running by default.
  - On macOS, install and launch [XQuartz](https://www.xquartz.org/)
    (make sure to go to XQuartz > Preferences > Security and check "Allow client connections").
  - On Windows, install and launch [VcXsrv](https://sourceforge.net/projects/vcxsrv/)
    (make sure to configure it to disable access control).
- Install [VScode](https://code.visualstudio.com/download) and add [Ledger's extension](https://marketplace.visualstudio.com/items?itemName=LedgerHQ.ledger-dev-tools).
- Open a terminal and clone `app-tron` with `git clone git@github.com:LedgerHQ/app-tron.git`.
- Open the `app-tron` folder with VSCode.
- Use Ledger extension's sidebar menu or open the tasks menu with `ctrl + shift + b`
  (`command + shift + b` on a Mac) to conveniently execute actions:
  - Build the app for the device model of your choice with `Build app`.
  - Test your binary on [Speculos](https://github.com/LedgerHQ/speculos) with `Run with emulator`.
  - You can also run functional tests, load the app on a physical device, and more.

> The terminal tab of VSCode will show you what commands the extension runs behind the scene.

## With a terminal

The [ledger-app-dev-tools](https://github.com/LedgerHQ/ledger-app-builder/pkgs/container/ledger-app-builder%2Fledger-app-dev-tools)
docker image contains all the required tools and libraries to **build**, **test** and **load** an application.

You can download it from the ghcr.io docker repository:

```shell
sudo docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

You can then enter this development environment by executing the following command
from the root directory of the application `git` repository:

### Linux (Ubuntu)

```shell
sudo docker run --rm -ti --user "$(id -u):$(id -g)" --privileged -v "/dev/bus/usb:/dev/bus/usb" -v "$(realpath .):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

### macOS

```shell
sudo docker run  --rm -ti --user "$(id -u):$(id -g)" --privileged -v "$(pwd -P):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

### Windows (with PowerShell)

```shell
docker run --rm -ti --privileged -v "$(Get-Location):/app" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
```

The application's code will be available from inside the docker container,
you can proceed to the following compilation steps to build your app.

# Compilation and load

To easily setup a development environment for compilation and loading on a physical device, you can use the [VSCode integration](#with-vscode)
whether you are on Linux, macOS or Windows.

If you prefer using a terminal to perform the steps manually, you can use the guide below.

## Compilation

Setup a compilation environment by following the [shell with docker approach](#with-a-terminal).

Be sure you checkout the submodule:

```shell
git submodule update --init
```

From inside the container, use the following command to build the app:

```shell
make DEBUG=1  # compile optionally with PRINTF
```

You can choose which device to compile and load for by setting the `BOLOS_SDK` environment variable to the following values:

- `BOLOS_SDK=$NANOX_SDK`
- `BOLOS_SDK=$NANOSP_SDK`
- `BOLOS_SDK=$STAX_SDK`
- `BOLOS_SDK=$FLEX_SDK`
- `BOLOS_SDK=$APEX_P_SDK`

## Loading on a physical device

This step will vary slightly depending on your platform.

> Your physical device must be connected, unlocked and the screen showing the dashboard (not inside an application).

### Linux (Ubuntu)

First make sure you have the proper udev rules added on your host.
See [udev-rules](https://github.com/LedgerHQ/udev-rules).

Then once you have [opened a terminal](#with-a-terminal) in the `app-builder` image and [built the app](#compilation-and-load)
for the device you want, run the following command:

```shell
# Run this command from the app-builder container terminal.
make load    # load the app on a Nano S by default
```

[Setting the BOLOS_SDK environment variable](#compilation-and-load) will allow you to load
on whichever supported device you want.

### macOS / Windows (with PowerShell)

> It is assumed you have [Python](https://www.python.org/downloads/) installed on your computer.

Run these commands on your host from the app's source folder once you have [built the app](#compilation-and-load)
for the device you want:

```shell
# Install Python virtualenv
python3 -m pip install virtualenv
# Create the 'ledger' virtualenv
python3 -m virtualenv ledger
```

Enter the Python virtual environment

- macOS: `source ledger/bin/activate`
- Windows: `.\ledger\Scripts\Activate.ps1`

```shell
# Install Ledgerblue (tool to load the app)
python3 -m pip install ledgerblue
# Load the app.
python3 -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

# APDUs

Supported commands are listed in the [APDU protocol documentation](docs/APDU.md).

# Tests

The Tron app comes with:

- Functional Tests implemented with Ledger's [Ragger](https://github.com/LedgerHQ/ragger) test framework.

Test cases are based on the following seed:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Select 12 words, enter 11 times `abandon` and one time `about`.

> This is the seed phrase we are going to use everywhere. Obviously don't use it to store your funds (unless testnet).\
> First Private key from this seed is b5a4cea271ff424d7c31dc12a3e43e401df7a40d7412a15750f3f0b6b5449a28 \
> Public key:  04ff21f8e64d3a3c0198edfbb7afdc79be959432e92e2f8a1984bb436a414b8edcec0345aad0c1bf7da04fd036dd7f9f617e30669224283d950fab9dd84831dc83\
>  Address: 41c8599111f29c1e1e061265b4af93ea1f274ad78a\
> Address base 58: TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH

## Functional Tests (Ragger based)

### Linux (Ubuntu)

On Linux, you can use [Ledger's VS Code extension](#with-vscode) to run the tests.
If you prefer not to, open a terminal and follow the steps below.

Install the tests requirements:

```shell
pip install -r tests/ragger/requirements.txt
```

Then you can:

Run the functional tests (here for flex but available for any device once you have built the binaries):

```shell
pytest tests/ --tb=short -v --device flex
```

Or run your app directly with Speculos

```shell
speculos build/flex/bin/app.elf
```

### macOS / Windows

To test your app on macOS or Windows, it is recommended to use [Ledger's VS Code extension](#with-vscode)
to quickly setup a working test environment.

You can use the following sequence of tasks and commands (all accessible in the **extension sidebar menu**):

- `Select target`
- `Build app`

Then you can choose to execute the functional tests:

- `Run tests`

Or simply run the app on the Speculos emulator:

- `Run with emulator`

## Contributing

Contributions are what makes the open source community such an amazing place to learn, inspire, and create.
Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request.
You can also simply open an issue with the tag `enhancement`.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/my-feature`)
3. Commit your Changes (`git commit -m 'feat: my new feature`)
4. Push to the Branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please try to follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
