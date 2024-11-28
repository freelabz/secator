# Changelog

## [0.7.0](https://github.com/freelabz/secator/compare/v0.6.0...v0.7.0) (2024-11-13)


### Features

* **`bup`:** add proxy option and progress indicator ([#444](https://github.com/freelabz/secator/issues/444)) ([d5c63c8](https://github.com/freelabz/secator/commit/d5c63c81c6465a142ce70e4800effc02d526a243))
* **`dnsx`:** add IP output type on dnsx A record  ([#426](https://github.com/freelabz/secator/issues/426)) ([629439e](https://github.com/freelabz/secator/commit/629439e459a6eefd5cbe68e9fc3a317371ba7987))
* **`naabu`/`nmap`:** help for defaults and change workflow opts ([#438](https://github.com/freelabz/secator/issues/438)) ([4dd0055](https://github.com/freelabz/secator/commit/4dd00556648e691a093887d294325b00409ac04a))
* **`nmap`:** add udp scan (`-sU`) and change default scan opts ([#418](https://github.com/freelabz/secator/issues/418)) ([36c6ff3](https://github.com/freelabz/secator/commit/36c6ff3766f88ac311c1bfea86a1b5e8686dd94e))
* add url_bypass workflow based on bup ([e96b1bc](https://github.com/freelabz/secator/commit/e96b1bc9906cd2f9aa3eb5b3770594811f242abd))
* chunk dalfox input by 1 ([#443](https://github.com/freelabz/secator/issues/443)) ([26c38d7](https://github.com/freelabz/secator/commit/26c38d79e89be3d35f464e89c6973b7beadb6ac4))
* **cli:** misc bug fixes and features ([#445](https://github.com/freelabz/secator/issues/445)) ([fccfdb8](https://github.com/freelabz/secator/commit/fccfdb8ca38dcd3a2c559429a7d58d46ecac49a6))
* **hooks:** explicit output type yield in static hooks ([#439](https://github.com/freelabz/secator/issues/439)) ([2d1f8e6](https://github.com/freelabz/secator/commit/2d1f8e6b7b77210028efe2c2c56866efbd6b0152))
* **katana:** add form_fill option ([#419](https://github.com/freelabz/secator/issues/419)) ([bebddb1](https://github.com/freelabz/secator/commit/bebddb1e2fae460403adda2d84b9ae515ca977aa))
* **refactor:** improve performance, add on_interval hook, rework CLI opts ([#473](https://github.com/freelabz/secator/issues/473)) ([4a22a70](https://github.com/freelabz/secator/commit/4a22a7082fe1edf50644034cfc54b11653b47aa4))
* **runner:** add GCS driver and secator threads ([#476](https://github.com/freelabz/secator/issues/476)) ([cae475a](https://github.com/freelabz/secator/commit/cae475a2fe15742ccd80d40c28ad41aa1ffc5348))
* **runner:** add skip_if_no_inputs to workflows ([#482](https://github.com/freelabz/secator/issues/482)) ([5546b82](https://github.com/freelabz/secator/commit/5546b82756d6aad0d227072d5a3b1149c44306e8))
* **runner:** on serialized hooks ([#424](https://github.com/freelabz/secator/issues/424)) ([fde6cd7](https://github.com/freelabz/secator/commit/fde6cd7f6cba015b08b370bfd14b0aca3f4a4018))
* **runner:** rework Celery core and mix fixes ([#450](https://github.com/freelabz/secator/issues/450)) ([b72f152](https://github.com/freelabz/secator/commit/b72f15286bb29ae60568309907d4dad41d4fbacb))
* sudo prompt check test ([#432](https://github.com/freelabz/secator/issues/432)) ([f45b123](https://github.com/freelabz/secator/commit/f45b1230fd6313342ebdda5a359c1285f2d80aa8))
* sudo prompts in non-tty mode ([#431](https://github.com/freelabz/secator/issues/431)) ([0e26b55](https://github.com/freelabz/secator/commit/0e26b55c168bfd69c212bc7667ef1b97e89e6bd5))
* **tasks:** bbot integration ([#375](https://github.com/freelabz/secator/issues/375)) ([2f0dea4](https://github.com/freelabz/secator/commit/2f0dea4f4cac3370129d0adf0000c8d0efa54361))
* **tasks:** bup integration ([#398](https://github.com/freelabz/secator/issues/398)) ([ed636aa](https://github.com/freelabz/secator/commit/ed636aad7d90baa7b3b73baebc8f5be002dd796a))


### Bug Fixes

* **cli:** proper opts override for workflows ([#436](https://github.com/freelabz/secator/issues/436)) ([1d1eaa3](https://github.com/freelabz/secator/commit/1d1eaa3283b3d5e9650b452e3865476e6a60a086))
* **dalfox:** restore input_chunk_size to default ([8f0a3b4](https://github.com/freelabz/secator/commit/8f0a3b4976e20afc2fb708483c7f8885b2b9f3d9))
* dnsx parsing output loading error ([#422](https://github.com/freelabz/secator/issues/422)) ([b9e98da](https://github.com/freelabz/secator/commit/b9e98da2b5378957076e1d8f0afd3948d5bcb5f6))
* empty CVE should pass ([#478](https://github.com/freelabz/secator/issues/478)) ([0644d68](https://github.com/freelabz/secator/commit/0644d68ccb92a4c38e8210e39f14f0850d84348d))
* gcs bug with empty paths ([549ac4c](https://github.com/freelabz/secator/commit/549ac4c8e7391a829cf1a6c5a43ad291bec1b34a))
* gcs bug with empty paths ([2d57e1a](https://github.com/freelabz/secator/commit/2d57e1ad4669587cf0abb0a59b0918cf72107d72))
* get_opt_value default value and reorg hooks ([#429](https://github.com/freelabz/secator/issues/429)) ([a44a36d](https://github.com/freelabz/secator/commit/a44a36d37f888787927ec6dfc891e86dab071aa4))
* mix bugfixes for stable release ([b743925](https://github.com/freelabz/secator/commit/b7439258c9cdadc7bd14a0a0b49e2db2d0f5b537))
* nmap defaults ([396f68a](https://github.com/freelabz/secator/commit/396f68a325a5a8f1a9379d314979dbf85a9c95c7))
* **nmap:** undefined service name ([#437](https://github.com/freelabz/secator/issues/437)) ([596f1af](https://github.com/freelabz/secator/commit/596f1aff53e9add73e1587497aee82465d212300))
* runner opts processing ([#477](https://github.com/freelabz/secator/issues/477)) ([d788e9d](https://github.com/freelabz/secator/commit/d788e9d3e508a849119d418bcc5ce371c6c53c6c))
* runner toDict() errors ([#475](https://github.com/freelabz/secator/issues/475)) ([b43c866](https://github.com/freelabz/secator/commit/b43c8669808651368536fa121be2ce79de7556aa))
* **runner:** bug with no inputs ([#483](https://github.com/freelabz/secator/issues/483)) ([4db7b46](https://github.com/freelabz/secator/commit/4db7b460a949e6b74b5837f0f1e3b5ca51b39094))
* **url_vuln:** repair bad condition ([214c8ab](https://github.com/freelabz/secator/commit/214c8abf7cad4916c8301ff056d894cc0bc26b28))


### Documentation

* add package json ([#415](https://github.com/freelabz/secator/issues/415)) ([f9a7c2f](https://github.com/freelabz/secator/commit/f9a7c2fc5df11506cce0d81babf1f7790b80465a))

## [0.6.0](https://github.com/freelabz/secator/compare/v0.5.2...v0.6.0) (2024-07-25)


### Features

* add duplicate finder to mongodb hooks ([#409](https://github.com/freelabz/secator/issues/409)) ([fb0e11c](https://github.com/freelabz/secator/commit/fb0e11cd2b64bf51bc862f47243c8c0602d3d5e9))
* basic helm chart ([#408](https://github.com/freelabz/secator/issues/408)) ([6b2f84f](https://github.com/freelabz/secator/commit/6b2f84f61bd8eccf2cdd61b6ffdc2eb4489240bc))


### Bug Fixes

* Dockerfile broken apt install ([#407](https://github.com/freelabz/secator/issues/407)) ([c023279](https://github.com/freelabz/secator/commit/c02327968ecea816004636801684b336735df439))
* **tasks:** duplicate meta opt entry ([#401](https://github.com/freelabz/secator/issues/401)) ([ae56aa6](https://github.com/freelabz/secator/commit/ae56aa62f5a18936a1787547e37bbe636e6e43c3))

## [0.5.2](https://github.com/freelabz/secator/compare/v0.5.1...v0.5.2) (2024-05-07)


### Bug Fixes

* **nuclei,katana:** add -sr flag and write http responses and screenshot to correct folder ([#395](https://github.com/freelabz/secator/issues/395)) ([1a51790](https://github.com/freelabz/secator/commit/1a51790c9231f593631c2780b6d5e0fa89f1aa55))

## [0.5.1](https://github.com/freelabz/secator/compare/v0.5.0...v0.5.1) (2024-05-06)


### Bug Fixes

* **output:** add headers to Url and print HTTP method when not GET ([#390](https://github.com/freelabz/secator/issues/390)) ([5a87d7b](https://github.com/freelabz/secator/commit/5a87d7b8bc1dd098999f3864952e98068fd32efc))
* **report:** do not remove duplicate in reports by default ([#392](https://github.com/freelabz/secator/issues/392)) ([7d74ae8](https://github.com/freelabz/secator/commit/7d74ae80bfd99c31714a5e7e25f2bd1caa642eb4))

## [0.5.0](https://github.com/freelabz/secator/compare/v0.4.1...v0.5.0) (2024-05-03)


### Features

* add searchsploit output fields ([#278](https://github.com/freelabz/secator/issues/278)) ([00872c4](https://github.com/freelabz/secator/commit/00872c4a7f9b1ec76ee1bfd7a00919d53cbdb30a))
* **cli:** add report list / export commands ([#367](https://github.com/freelabz/secator/issues/367)) ([ab396a3](https://github.com/freelabz/secator/commit/ab396a3098c6d4c46cf9c9b29bd5c54579421646))
* **config:** load external tasks from template dir ([#373](https://github.com/freelabz/secator/issues/373)) ([0c63c02](https://github.com/freelabz/secator/commit/0c63c02c8eca477a6752f4af466c4303801019de))


### Bug Fixes

* **cli:** catch JSON parse errors ([#378](https://github.com/freelabz/secator/issues/378)) ([5e3d7f2](https://github.com/freelabz/secator/commit/5e3d7f2d2938a857e7599a429a6cfabf3b12347b))
* **nmap:** resolve -sS tcp syn stealth issue ([#376](https://github.com/freelabz/secator/issues/376)) ([a3efc65](https://github.com/freelabz/secator/commit/a3efc651dfa4d8fa34d611b9aea2e156352fdc45))

## [0.4.1](https://github.com/freelabz/secator/compare/v0.4.0...v0.4.1) (2024-04-30)


### Bug Fixes

* failed addons import ([#368](https://github.com/freelabz/secator/issues/368)) ([aee7ede](https://github.com/freelabz/secator/commit/aee7edeee1e96292e637b9161034f0d628a1f386))
* load dotenv before config import ([#370](https://github.com/freelabz/secator/issues/370)) ([ba2ea8e](https://github.com/freelabz/secator/commit/ba2ea8e3624dda7268d3788c0541fc0d37195358))

## [0.4.0](https://github.com/freelabz/secator/compare/v0.3.6...v0.4.0) (2024-04-27)


### Features

* `nuclei` - add "meta" items to extra_data ([#329](https://github.com/freelabz/secator/issues/329)) ([d986e01](https://github.com/freelabz/secator/commit/d986e01ed10bfd58c57565e24f053cf4ffb165b5))
* add offline mode ([#314](https://github.com/freelabz/secator/issues/314)) ([6b55e99](https://github.com/freelabz/secator/commit/6b55e99a9e60a102afaf71a49148a8aec1b2e3dc))
* add secator configuration loader ([#313](https://github.com/freelabz/secator/issues/313)) ([9b9ab7b](https://github.com/freelabz/secator/commit/9b9ab7b1c394bd77c986fcb755d19d1b887228cf))


### Bug Fixes

* add alias for config command and reload help screenshot ([#324](https://github.com/freelabz/secator/issues/324)) ([3dbc9ad](https://github.com/freelabz/secator/commit/3dbc9adf7a3b12dbf5bdcaa2224297d58b1e2fd8))
* add nmap --top-ports option ([#339](https://github.com/freelabz/secator/issues/339)) ([6352be7](https://github.com/freelabz/secator/commit/6352be7350890c38e521d98b89e7e634ed8c8684))
* add redis addon missing warning on celery worker ([#310](https://github.com/freelabz/secator/issues/310)) ([c0afc3a](https://github.com/freelabz/secator/commit/c0afc3a068140f9811845c05c8d3763d932407de))
* better vuln detection ([#349](https://github.com/freelabz/secator/issues/349)) ([150b603](https://github.com/freelabz/secator/commit/150b6030e6702f599b8a67ba53bef4c2e675e90a))
* **config:** broken list values with 0 or 1 element ([#364](https://github.com/freelabz/secator/issues/364)) ([7ef7a5e](https://github.com/freelabz/secator/commit/7ef7a5e27604df53868d2b670439a0a7150e8af1))
* **docker:** pull remote DockerHub images in Compose ([#363](https://github.com/freelabz/secator/issues/363)) ([dce6d8a](https://github.com/freelabz/secator/commit/dce6d8a5d722aa85c1fc2592f44738b6bfe79b04))
* grype integration test ([#327](https://github.com/freelabz/secator/issues/327)) ([33ddb84](https://github.com/freelabz/secator/commit/33ddb84836965c4bff6fd442c317de240e54ec3f))
* minor config tweaks ([#360](https://github.com/freelabz/secator/issues/360)) ([4631024](https://github.com/freelabz/secator/commit/46310245afe0b0d04a6b333175f28ffeab1659bb))
* next steps highlight ([#326](https://github.com/freelabz/secator/issues/326)) ([528c715](https://github.com/freelabz/secator/commit/528c715e4f20bceb9dbae85e99b707243d556aea))
* proper local file naming for sudo_killer.zip ([#330](https://github.com/freelabz/secator/issues/330)) ([f7e563f](https://github.com/freelabz/secator/commit/f7e563f3a4a20fd38f7167e2bd682ddb3eea6224))
* query CVEs without CPE match ([#321](https://github.com/freelabz/secator/issues/321)) ([d02e09c](https://github.com/freelabz/secator/commit/d02e09cc379afa85df25227f6c0bab4496031d78))
* switch payload sudo_killer to zip ([#318](https://github.com/freelabz/secator/issues/318)) ([2a92dc8](https://github.com/freelabz/secator/commit/2a92dc8d4a71cce71a85bb77747b8af2d5aed6c4))
* task description in remote mode ([#344](https://github.com/freelabz/secator/issues/344)) ([1140611](https://github.com/freelabz/secator/commit/1140611a1129c19bd306db33396ea3fa1bc88f25))
* truncated pickle error ([#334](https://github.com/freelabz/secator/issues/334)) ([663af17](https://github.com/freelabz/secator/commit/663af1777d07c7628a220ee627aece9fc83e6095))


### Documentation

* add VHS demo ([#293](https://github.com/freelabz/secator/issues/293)) ([70454a6](https://github.com/freelabz/secator/commit/70454a60053ef6ce3002565c07ede7b00b14e335))
* update README.md ([a0a19fb](https://github.com/freelabz/secator/commit/a0a19fb24cd297e98cb8716e691ed6fcf11475c6))
* update README.md ([341f5b8](https://github.com/freelabz/secator/commit/341f5b8cd049fd8e33ebfb525de0377d0a659df2))
* Update README.md ([98c986c](https://github.com/freelabz/secator/commit/98c986c644bbe62434c0a2fe72fe9eea606c2e8d))

## [0.3.6](https://github.com/freelabz/secator/compare/v0.3.5...v0.3.6) (2024-04-17)


### Bug Fixes

* broken reports folder on remote workers ([#307](https://github.com/freelabz/secator/issues/307)) ([9a7a1f1](https://github.com/freelabz/secator/commit/9a7a1f1c449c688701b02be66e98d3434073bbb0))
* searchsploit install ([#306](https://github.com/freelabz/secator/issues/306)) ([040cfaf](https://github.com/freelabz/secator/commit/040cfaf6968ae120241fdd6a74a9a6cd5fa0631d))

## [0.3.5](https://github.com/freelabz/secator/compare/v0.3.4...v0.3.5) (2024-04-17)


### Bug Fixes

* Celery control folder ([#298](https://github.com/freelabz/secator/issues/298)) ([3cbc0a3](https://github.com/freelabz/secator/commit/3cbc0a37d06c9b3a20eb0005b1cb68b484d22d15))
* remove pkg_resources in favor of packaging ([#304](https://github.com/freelabz/secator/issues/304)) ([6cf478c](https://github.com/freelabz/secator/commit/6cf478c1f1c4b7363d1710e634686ede8a209594))
* typo in `requires-python` in pyproject.toml ([#303](https://github.com/freelabz/secator/issues/303)) ([7a7766c](https://github.com/freelabz/secator/commit/7a7766caba0faa98406764fa1bb5ad2eae346302))


### Documentation

* update README.md ([8f1b1c1](https://github.com/freelabz/secator/commit/8f1b1c1cb852a88d80aa15379962aaa36afc7635))
* update SECURITY.md ([6518dd6](https://github.com/freelabz/secator/commit/6518dd646c0358e661e186edf28b4fb0494bf712))

## [0.3.4](https://github.com/freelabz/secator/compare/v0.3.3...v0.3.4) (2024-04-15)


### Bug Fixes

* install cariddi from GitHub releases ([#290](https://github.com/freelabz/secator/issues/290)) ([21c9078](https://github.com/freelabz/secator/commit/21c90787713fc08fcf375b37b144a4b86ebc49ee))
* install cariddi from GitHub releases ([#292](https://github.com/freelabz/secator/issues/292)) ([8be216b](https://github.com/freelabz/secator/commit/8be216b01cb2fbc82aca7be32fc190adf17bda52))

## [0.3.3](https://github.com/freelabz/secator/compare/v0.3.2...v0.3.3) (2024-04-13)


### Bug Fixes

* tools install ([#288](https://github.com/freelabz/secator/issues/288)) ([0608a1f](https://github.com/freelabz/secator/commit/0608a1f408551942fca3c729b975b1acbb588903))


### Documentation

* update Docker instructions ([21afd3f](https://github.com/freelabz/secator/commit/21afd3fea06bb2f8ca11a37ec14a5a78d5c0ecb1))

## [0.3.2](https://github.com/freelabz/secator/compare/v0.3.1...v0.3.2) (2024-04-12)


### Bug Fixes

* do not create scripts/ folder ([#273](https://github.com/freelabz/secator/issues/273)) ([8fdaf09](https://github.com/freelabz/secator/commit/8fdaf09d4d1f3fbac7def995b99e9bc4f4f5020d))
* health table padding ([#274](https://github.com/freelabz/secator/issues/274)) ([4f976bd](https://github.com/freelabz/secator/commit/4f976bdaecef7c29a2c6b21ddb29299745dfe5c9))
* install script ([#276](https://github.com/freelabz/secator/issues/276)) ([e27b339](https://github.com/freelabz/secator/commit/e27b3391ea3a5c5a7898d3c02a5f409be44255f8))


### Documentation

* update docker setup ([#279](https://github.com/freelabz/secator/issues/279)) ([9b56e75](https://github.com/freelabz/secator/commit/9b56e75b114f294d222660dbae4f2e6b5e1369cd))

## [0.3.1](https://github.com/freelabz/secator/compare/v0.3.0...v0.3.1) (2024-04-11)


### Bug Fixes

* download default wordlists if missing ([#261](https://github.com/freelabz/secator/issues/261)) ([7bec2a4](https://github.com/freelabz/secator/commit/7bec2a46d054aa7d3702eb77d25b9f791f5cc9c5))
* rework init & tools install ([#271](https://github.com/freelabz/secator/issues/271)) ([6c477fc](https://github.com/freelabz/secator/commit/6c477fc99d5f1dd625423ba27dc563acc50194bf))
* wrong hook name in debug output ([#262](https://github.com/freelabz/secator/issues/262)) ([f2ee367](https://github.com/freelabz/secator/commit/f2ee36779615bd2c1ef1f80679a9cc77e9e592d6))

## [0.3.0](https://github.com/freelabz/secator/compare/v0.2.0...v0.3.0) (2024-04-09)


### Features

* add health command and update check ([#258](https://github.com/freelabz/secator/issues/258)) ([289b86a](https://github.com/freelabz/secator/commit/289b86ac2c278f02102d8824d3de5cf71e3778ae))
* rework install to use pre-packaged binaries when possible ([#253](https://github.com/freelabz/secator/issues/253)) ([b391fe8](https://github.com/freelabz/secator/commit/b391fe8cfdf991b50435c4f53f470e3cea0150ee))


### Bug Fixes

* health -json output ([#257](https://github.com/freelabz/secator/issues/257)) ([4477bb2](https://github.com/freelabz/secator/commit/4477bb25170e80fca1be5985a3b198dd7b423e5f))
* txt output bug ([#256](https://github.com/freelabz/secator/issues/256)) ([fca301d](https://github.com/freelabz/secator/commit/fca301d24c5d9999fef9ae13b8e64c099a65ab95))

## [0.2.0](https://github.com/freelabz/secator/compare/v0.1.1...v0.2.0) (2024-04-08)


### Features

* add build & release CLI commands ([#247](https://github.com/freelabz/secator/issues/247)) ([775eba1](https://github.com/freelabz/secator/commit/775eba16d3a6f9d8cbc83f81daed85fb806fe6db))


### Bug Fixes

* docker build & push ([#250](https://github.com/freelabz/secator/issues/250)) ([7cebd9f](https://github.com/freelabz/secator/commit/7cebd9fe61f6dbb76e9f78fcbcd3514d68204c87))
* install issues & docs ([#243](https://github.com/freelabz/secator/issues/243)) ([0447148](https://github.com/freelabz/secator/commit/0447148c89f13884cbc14579d953e0d3e067cbe2)), closes [#242](https://github.com/freelabz/secator/issues/242) [#241](https://github.com/freelabz/secator/issues/241) [#240](https://github.com/freelabz/secator/issues/240) [#239](https://github.com/freelabz/secator/issues/239)
