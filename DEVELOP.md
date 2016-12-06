###	SETUP

**Checkout**: 

* `git clone 'url to repository'`

**Fetch dependencies**: 

* Fetch submodule (custom KeePass source): `git submodule update --init -- "extern/KeePass"`
* Run from Package Manager Console inside Visual Studio `Update-Package -Reinstall`

### TODOs

* Renaming of users changes name of export target - all clients need to remove the old source and readd the source with the changed name
* Shared nodes could be highlighted using a link or share symbol within the icon 
* enforce a consistent way of sharing nodes - possibly using virtual groups collecting all shared nodes inside a special KeeShare group/subtree