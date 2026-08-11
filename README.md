# hk4e-patch-universal

Universal encryption and redirection patch for Genshin Impact, to allow research into and preserving older versions, by adding interoperability with third party servers.

The current live version of the game, while sometimes potentially supported through overlaps with older versions, is not the target of this fork.
This means Pull Requests targeting specifically the latest version will not be accepted, as long as it's the current live version.    

## Currently supported
* 1.x to 3.1 (as `version.dll`)
* 4.8 to 6.x (as `Astrolabe.dll`)

## How to use
* Put the .dll file into the root of  the game.
* Start the game with either the enviroment variables or paramters set, that you want to use

### Options
| paramter     | variable           | description                                          |
|--------------|--------------------|------------------------------------------------------|
| `--redirect` | PATCH_REDIRECT     | sets a redirect target for sdk and dispatch requests |
| `--dispatch` | PATCH_DISPATCH_URL | redirect url for dispatch requests                   |
| `--sdk`      | PATCH_SDK_URL      | redirect url for sdk/login requests                  |

### proton/wine
* Make sure to set proton to load the `version.dll` from the game folder by setting the overwrites to:
  * `WINEDLLOVERRIDES="version=n,b"`
  * e.g. for proton via steam: `WINEDLLOVERRIDES="wlanapi=n,b;winhttp=n,b;version=n,b" %command% --redirect=127.0.0.1:8443`

## Building
### windows
run `cargo build --release`
### linux
run `cargo build --target x86_64-pc-windows-gnu --release`

## Credits
### Code/patches
* [thexeondev](https://github.com/thexeondev) for the original universal patch, thats the base for this one
* [pmagixc](https://github.com/pmagixc/) for the old hoyopass patch and some pattern updates
* [Kitkat](https://github.com/kitkat033/) for 6.5+ offsets and the new hoyopass patch from Starlight-Patch (before it got taken down)

### Testing and other resources
* [HRB-YuPai / LoneOne](https://github.com/HRB-YuPai) 1.x to 3.x
* [scooterboo / Nazrin](https://github.com/scooterboo) 5.x/early 6.x


## Not affiliated with or endorsed by Hoyoverse/miHoYo
