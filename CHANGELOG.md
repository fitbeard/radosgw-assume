# Changelog

## [3.0.0](https://github.com/fitbeard/radosgw-assume/compare/v2.0.0...v3.0.0) (2026-08-18)


### ⚠ BREAKING CHANGES

* require profile selection through flag ([#76](https://github.com/fitbeard/radosgw-assume/issues/76))

### Features

* add authenticated shell command ([#80](https://github.com/fitbeard/radosgw-assume/issues/80)) ([0b7f8c8](https://github.com/fitbeard/radosgw-assume/commit/0b7f8c843b68ce32a104e100e2824c50b53c03e7))
* add AWS credential_process command ([#87](https://github.com/fitbeard/radosgw-assume/issues/87)) ([1a3bd1b](https://github.com/fitbeard/radosgw-assume/commit/1a3bd1bbf2e40cfa3ea4116c2c00e75bfa87e9d8))
* add brew release ([4ab6fc3](https://github.com/fitbeard/radosgw-assume/commit/4ab6fc3486fd58644c7dc583e82ca0e015f41860))
* add core performance baselines ([#110](https://github.com/fitbeard/radosgw-assume/issues/110)) ([39b10aa](https://github.com/fitbeard/radosgw-assume/commit/39b10aafb715d5f9d15b37609fec1385795c4465))
* add credential cache management ([#90](https://github.com/fitbeard/radosgw-assume/issues/90)) ([a9cd597](https://github.com/fitbeard/radosgw-assume/commit/a9cd597f19a86a02d5ed26da080e0c5b4efbc05a))
* add custom role_session_name option ([bcab432](https://github.com/fitbeard/radosgw-assume/commit/bcab4323298628b5cd9e0aff67aa2887012625dd))
* Add documentation and examples ([bb58272](https://github.com/fitbeard/radosgw-assume/commit/bb58272d3f2348126c512c19a2bad00f9e9ce465))
* Add documentation and examples ([6a34c62](https://github.com/fitbeard/radosgw-assume/commit/6a34c62f5949f77c8990a57ff8556421ab172ecd))
* add exec command ([#79](https://github.com/fitbeard/radosgw-assume/issues/79)) ([08d7ea4](https://github.com/fitbeard/radosgw-assume/commit/08d7ea4fb59b40183d3cb092996ec92f928a7fac))
* add kubernetes examples ([483afe5](https://github.com/fitbeard/radosgw-assume/commit/483afe5249db0e00b5a15b02094ae60d1abfdf43))
* add kubernetes examples ([211b6db](https://github.com/fitbeard/radosgw-assume/commit/211b6dbc2391542750647f39fbd65e413b11ddc4))
* cache credential_process credentials securely ([#88](https://github.com/fitbeard/radosgw-assume/issues/88)) ([2c328a8](https://github.com/fitbeard/radosgw-assume/commit/2c328a8482aea4cf11c5ffbb43d2af5f23b04e90))
* centralize HTTP client construction ([#82](https://github.com/fitbeard/radosgw-assume/issues/82)) ([25901c4](https://github.com/fitbeard/radosgw-assume/commit/25901c4120d230a8fdd984ca3b98021d494e1587))
* cleanup and switch to golang 1.26 ([#62](https://github.com/fitbeard/radosgw-assume/issues/62)) ([a663df8](https://github.com/fitbeard/radosgw-assume/commit/a663df8f33131ca4e71627a27c929b64d4c5da9e))
* consolidate OIDC token handling ([#83](https://github.com/fitbeard/radosgw-assume/issues/83)) ([1d8d741](https://github.com/fitbeard/radosgw-assume/commit/1d8d741624113c2043ba451b42349c2448cd8fc6))
* discover OIDC provider endpoints ([#84](https://github.com/fitbeard/radosgw-assume/issues/84)) ([309e3ee](https://github.com/fitbeard/radosgw-assume/commit/309e3ee62e1921737e527c8b67031c6e38001354))
* improve error handling messages ([#13](https://github.com/fitbeard/radosgw-assume/issues/13)) ([1bc42b5](https://github.com/fitbeard/radosgw-assume/commit/1bc42b52c63682494e4907af06a3077e2222bbee))
* make AWS config loading deterministic ([#71](https://github.com/fitbeard/radosgw-assume/issues/71)) ([ac06ffd](https://github.com/fitbeard/radosgw-assume/commit/ac06ffd68da2f3052cefaf9d9b0870759f490b6e))
* make browser authentication flow testable ([#68](https://github.com/fitbeard/radosgw-assume/issues/68)) ([7c1d8f4](https://github.com/fitbeard/radosgw-assume/commit/7c1d8f406d5943c80617bd7eb1a1fd903502eb52))
* make device authentication flow testable ([#69](https://github.com/fitbeard/radosgw-assume/issues/69)) ([024876e](https://github.com/fitbeard/radosgw-assume/commit/024876eebf7022598712bd29a658fca4526775a8))
* require profile selection through flag ([#76](https://github.com/fitbeard/radosgw-assume/issues/76)) ([646aae8](https://github.com/fitbeard/radosgw-assume/commit/646aae846fc1f3b21875f2c42914014da6c02a17))
* separate authenticated shell components ([#97](https://github.com/fitbeard/radosgw-assume/issues/97)) ([68d52b6](https://github.com/fitbeard/radosgw-assume/commit/68d52b613d6d402adf692e3243cbd1a2930be7e3))
* separate browser authentication components ([#95](https://github.com/fitbeard/radosgw-assume/issues/95)) ([51ca6a6](https://github.com/fitbeard/radosgw-assume/commit/51ca6a6bdf0cc2c390e238986f8347f490cbbdb0))
* separate CLI action execution ([#94](https://github.com/fitbeard/radosgw-assume/issues/94)) ([3c093cf](https://github.com/fitbeard/radosgw-assume/commit/3c093cf3e720c26e9416be1bb1936fa2f406a6b8))
* separate configuration loading and resolution ([#99](https://github.com/fitbeard/radosgw-assume/issues/99)) ([3280dd9](https://github.com/fitbeard/radosgw-assume/commit/3280dd9e8873e544c88108ee1421e9457eacb69e))
* separate credential cache components ([#98](https://github.com/fitbeard/radosgw-assume/issues/98)) ([2568227](https://github.com/fitbeard/radosgw-assume/commit/2568227b532d50c8cde1a5b183aabedf4fa9da2e))
* separate credential orchestration components ([#100](https://github.com/fitbeard/radosgw-assume/issues/100)) ([c51265e](https://github.com/fitbeard/radosgw-assume/commit/c51265e5676437da886600aae792afd37dba6359))
* separate device authentication components ([#102](https://github.com/fitbeard/radosgw-assume/issues/102)) ([978bc8c](https://github.com/fitbeard/radosgw-assume/commit/978bc8c65a16461604908bbf38f2a94e52a508b5))
* separate device authentication components ([#103](https://github.com/fitbeard/radosgw-assume/issues/103)) ([4864418](https://github.com/fitbeard/radosgw-assume/commit/4864418122810510dbf39019a1c375a19cae2f5b))
* separate OIDC authentication helpers ([#96](https://github.com/fitbeard/radosgw-assume/issues/96)) ([5a411ac](https://github.com/fitbeard/radosgw-assume/commit/5a411ac6dadf26bd2b27149a7f64606ee824a73f))
* separate STS request and error handling ([#101](https://github.com/fitbeard/radosgw-assume/issues/101)) ([ad25cfc](https://github.com/fitbeard/radosgw-assume/commit/ad25cfcb205c132a5ea5020e1d37af52ac3d72b4))
* simplify browser authentication orchestration ([#108](https://github.com/fitbeard/radosgw-assume/issues/108)) ([26dd4b7](https://github.com/fitbeard/radosgw-assume/commit/26dd4b7d30ebd24d36c4319ff30f0780b41f90ff))
* update release-please config ([#25](https://github.com/fitbeard/radosgw-assume/issues/25)) ([6e74d4b](https://github.com/fitbeard/radosgw-assume/commit/6e74d4bcdb231edf1b3005664878e915d6d67a2a))
* use typed credential request options ([#107](https://github.com/fitbeard/radosgw-assume/issues/107)) ([142fffe](https://github.com/fitbeard/radosgw-assume/commit/142fffef8cc47692c3a6e604c2d62d6d1de18ba3))
* use typed OIDC authentication options ([#105](https://github.com/fitbeard/radosgw-assume/issues/105)) ([8c27c28](https://github.com/fitbeard/radosgw-assume/commit/8c27c287664153c3cd1744f55022fd2f57ca556f))
* use typed STS assume-role options ([#106](https://github.com/fitbeard/radosgw-assume/issues/106)) ([1dbdae2](https://github.com/fitbeard/radosgw-assume/commit/1dbdae24075085fed4ab4791d5e0746e4f82acf3))


### Bug Fixes

* bound OIDC and STS request durations ([#65](https://github.com/fitbeard/radosgw-assume/issues/65)) ([6a5bdd2](https://github.com/fitbeard/radosgw-assume/commit/6a5bdd2ad4bb3f29a4dc2bd65bebd95adf7cc297))
* close device polling responses promptly and set PKCE method for device auth ([#63](https://github.com/fitbeard/radosgw-assume/issues/63)) ([7cebbe2](https://github.com/fitbeard/radosgw-assume/commit/7cebbe2fd1b2a2f5c90ffd71b1f24ad2782f2a53))
* harden browser callback lifecycle ([#64](https://github.com/fitbeard/radosgw-assume/issues/64)) ([5054241](https://github.com/fitbeard/radosgw-assume/commit/50542416fa3d777b5214d5cfffdca7362460e822))
* harden network error handling ([#78](https://github.com/fitbeard/radosgw-assume/issues/78)) ([c7839fd](https://github.com/fitbeard/radosgw-assume/commit/c7839fd145ffc3408c877d58c97695f32c44f270))
* harden OIDC response handling ([#77](https://github.com/fitbeard/radosgw-assume/issues/77)) ([180bc6d](https://github.com/fitbeard/radosgw-assume/commit/180bc6db4c7f20b1f9758f3b31cfeee2e7926c6a))
* harden source profile resolution ([#75](https://github.com/fitbeard/radosgw-assume/issues/75)) ([ac40c6e](https://github.com/fitbeard/radosgw-assume/commit/ac40c6eed6173f12fdf9802872d74dbd547684af))
* honor OIDC device authorization expiry ([#91](https://github.com/fitbeard/radosgw-assume/issues/91)) ([7023795](https://github.com/fitbeard/radosgw-assume/commit/7023795c485a2fa8be9e48c7012f8184b5d2838b))
* improve secure random string generation ([#81](https://github.com/fitbeard/radosgw-assume/issues/81)) ([d93ee78](https://github.com/fitbeard/radosgw-assume/commit/d93ee78d951293aaf821bc76d57a7d5b0dda408b))
* make progress indicator shutdown idempotent ([#70](https://github.com/fitbeard/radosgw-assume/issues/70)) ([3fe03c4](https://github.com/fitbeard/radosgw-assume/commit/3fe03c4d84055222c8dc69bfa5610c8286958a70))
* naming pattern ([f6ea0f4](https://github.com/fitbeard/radosgw-assume/commit/f6ea0f48c97bc0265f7206f6a0f16734f22eb62c))
* prevent accidental credential output to terminal ([#109](https://github.com/fitbeard/radosgw-assume/issues/109)) ([c5d6221](https://github.com/fitbeard/radosgw-assume/commit/c5d6221c14dd6329546b0cda5c7e8d57339ade95))
* propagate context through authentication requests ([#93](https://github.com/fitbeard/radosgw-assume/issues/93)) ([a2e306c](https://github.com/fitbeard/radosgw-assume/commit/a2e306c5bbade5abba0b384190ffff638a7e3e81))
* remove duplicated code ([#12](https://github.com/fitbeard/radosgw-assume/issues/12)) ([daf134e](https://github.com/fitbeard/radosgw-assume/commit/daf134e272d9019c051d54033a21c936e41993a6))
* remove obsolete configuration APIs ([#85](https://github.com/fitbeard/radosgw-assume/issues/85)) ([044f322](https://github.com/fitbeard/radosgw-assume/commit/044f3221c50ea8f298a8b25d13fbc7c1f8848079))
* remove the quarantine bit from the binary on MacOS ([#35](https://github.com/fitbeard/radosgw-assume/issues/35)) ([55595c3](https://github.com/fitbeard/radosgw-assume/commit/55595c34410310f6d34d751d3e18d57f4cb78542))
* separate command argument parsing ([#92](https://github.com/fitbeard/radosgw-assume/issues/92)) ([8ef91de](https://github.com/fitbeard/radosgw-assume/commit/8ef91dec1e0dc03d78201e16cd35bb82754d1fa0))
* support interactive exports through source ([#86](https://github.com/fitbeard/radosgw-assume/issues/86)) ([3180c44](https://github.com/fitbeard/radosgw-assume/commit/3180c4463cd8c22541480ef6d65ac61c46486fa8))
* validate configuration values consistently ([#104](https://github.com/fitbeard/radosgw-assume/issues/104)) ([0aa6536](https://github.com/fitbeard/radosgw-assume/commit/0aa65361f4dccd1cc7da388f8b244d093ce0bb46))
* validate STS credential responses ([#74](https://github.com/fitbeard/radosgw-assume/issues/74)) ([6c68118](https://github.com/fitbeard/radosgw-assume/commit/6c681188043d08c1791fee9e04b2d541fe47af50))


### Documentation

* add README ([3acaeb4](https://github.com/fitbeard/radosgw-assume/commit/3acaeb407eb3976b35e307465338e6cfe68527c7))
* fix AWS config keys in README ([#72](https://github.com/fitbeard/radosgw-assume/issues/72)) ([ea57a1f](https://github.com/fitbeard/radosgw-assume/commit/ea57a1f55bd4b7fd1e87ca982cec78d2e87bcaff))


### Miscellaneous

* clean docs ([#15](https://github.com/fitbeard/radosgw-assume/issues/15)) ([ad1c5b4](https://github.com/fitbeard/radosgw-assume/commit/ad1c5b4c324c1f3f372b449546499c7d64cf8962))
* **deps:** Bump actions/checkout from 6 to 7 ([#51](https://github.com/fitbeard/radosgw-assume/issues/51)) ([7b5499b](https://github.com/fitbeard/radosgw-assume/commit/7b5499bc80aad0ce0f315fc71ccd18ed30bd8406))
* **deps:** Bump actions/setup-go from 6 to 7 ([#55](https://github.com/fitbeard/radosgw-assume/issues/55)) ([1adc1da](https://github.com/fitbeard/radosgw-assume/commit/1adc1dafe026946b3aee90b43c31c49162ebba25))
* **deps:** Bump charm.land/lipgloss/v2 from 2.0.1 to 2.0.6 ([#89](https://github.com/fitbeard/radosgw-assume/issues/89)) ([3125d34](https://github.com/fitbeard/radosgw-assume/commit/3125d34feb366e53d43eae68398ba503b284a430))
* **deps:** Bump github.com/aws/aws-sdk-go-v2 from 1.41.0 to 1.41.1 ([#9](https://github.com/fitbeard/radosgw-assume/issues/9)) ([7985402](https://github.com/fitbeard/radosgw-assume/commit/7985402d7e5d1c825ec383ad226f55a61c05f25a))
* **deps:** Bump github.com/aws/aws-sdk-go-v2 from 1.41.2 to 1.41.3 ([#24](https://github.com/fitbeard/radosgw-assume/issues/24)) ([ca646bf](https://github.com/fitbeard/radosgw-assume/commit/ca646bf4a58768d838e317b6fd5b8ec00f74d4c2))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#19](https://github.com/fitbeard/radosgw-assume/issues/19)) ([3cce704](https://github.com/fitbeard/radosgw-assume/commit/3cce7040b16f1a3740c3382b6752a84375ae854f))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#22](https://github.com/fitbeard/radosgw-assume/issues/22)) ([5346d77](https://github.com/fitbeard/radosgw-assume/commit/5346d77b7c2334c83a4796a830e3db2111fe3bfb))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#28](https://github.com/fitbeard/radosgw-assume/issues/28)) ([6eeedba](https://github.com/fitbeard/radosgw-assume/commit/6eeedba646596537dced0e822acf84109cf84a26))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#54](https://github.com/fitbeard/radosgw-assume/issues/54)) ([437fbfc](https://github.com/fitbeard/radosgw-assume/commit/437fbfc92fe8e6cae883f821311ada5b8dc0e8c6))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#8](https://github.com/fitbeard/radosgw-assume/issues/8)) ([06f1e86](https://github.com/fitbeard/radosgw-assume/commit/06f1e86b0465edae2332ce38030d3a338b10178c))
* **deps:** Bump github.com/aws/smithy-go from 1.24.2 to 1.24.3 ([#31](https://github.com/fitbeard/radosgw-assume/issues/31)) ([2f0cf95](https://github.com/fitbeard/radosgw-assume/commit/2f0cf95406a806e225f07ccb991fc0c276a99279))
* **deps:** Bump github.com/aws/smithy-go from 1.25.0 to 1.25.1 ([#39](https://github.com/fitbeard/radosgw-assume/issues/39)) ([1c01a48](https://github.com/fitbeard/radosgw-assume/commit/1c01a48bfd3db6f23805b0084fa576f25e36966a))
* **deps:** Bump github.com/aws/smithy-go from 1.27.1 to 1.27.2 ([#47](https://github.com/fitbeard/radosgw-assume/issues/47)) ([5059e06](https://github.com/fitbeard/radosgw-assume/commit/5059e067b01a14fb8324bcf0ff16f8fe88e26d7b))
* **deps:** Bump github.com/aws/smithy-go from 1.27.3 to 1.27.4 ([#56](https://github.com/fitbeard/radosgw-assume/issues/56)) ([55af1c4](https://github.com/fitbeard/radosgw-assume/commit/55af1c48dff2bcaafe7b558ff13d2fcf50170bf7))
* **deps:** Bump github.com/aws/smithy-go from 1.27.4 to 1.27.6 ([#58](https://github.com/fitbeard/radosgw-assume/issues/58)) ([7ef4cdf](https://github.com/fitbeard/radosgw-assume/commit/7ef4cdfb1d6a76c04a982a408048cdbec88b80b0))
* **deps:** Bump googleapis/release-please-action from 4 to 5 ([#40](https://github.com/fitbeard/radosgw-assume/issues/40)) ([7d187eb](https://github.com/fitbeard/radosgw-assume/commit/7d187ebf5338444ab5e41ae53a9a091a1715c8b1))
* **deps:** Bump gopkg.in/ini.v1 from 1.67.0 to 1.67.1 ([#7](https://github.com/fitbeard/radosgw-assume/issues/7)) ([5452bfd](https://github.com/fitbeard/radosgw-assume/commit/5452bfdb804ed27f4f45a00bccd50138f85015c6))
* **deps:** Bump gopkg.in/ini.v1 from 1.67.1 to 1.67.2 ([#42](https://github.com/fitbeard/radosgw-assume/issues/42)) ([c9aca5d](https://github.com/fitbeard/radosgw-assume/commit/c9aca5d19dc6fa0ac04943dab158eaa2cc4a4231))
* **deps:** Bump gopkg.in/ini.v1 from 1.67.2 to 1.67.3 ([#49](https://github.com/fitbeard/radosgw-assume/issues/49)) ([12a1b0c](https://github.com/fitbeard/radosgw-assume/commit/12a1b0c35f66bb9b57659a371fb0dc6ba4476c3b))
* **deps:** Bump goreleaser/goreleaser-action from 6 to 7 ([#18](https://github.com/fitbeard/radosgw-assume/issues/18)) ([b06475b](https://github.com/fitbeard/radosgw-assume/commit/b06475bbd8d7cb979ca4646cf328d8231fa2eea9))
* **deps:** Bump the aws-sdk group with 2 updates ([#33](https://github.com/fitbeard/radosgw-assume/issues/33)) ([ab395c9](https://github.com/fitbeard/radosgw-assume/commit/ab395c9df9109028eb0f6be1e4df357eef35c196))
* **deps:** Bump the aws-sdk group with 2 updates ([#37](https://github.com/fitbeard/radosgw-assume/issues/37)) ([6fb6df5](https://github.com/fitbeard/radosgw-assume/commit/6fb6df5ca53a9e94c1619bc02c9aa9914d010267))
* **deps:** Bump the aws-sdk group with 2 updates ([#41](https://github.com/fitbeard/radosgw-assume/issues/41)) ([8f17a92](https://github.com/fitbeard/radosgw-assume/commit/8f17a922f01bd48fb858bf67ddcba89b57ea3a8f))
* **deps:** Bump the aws-sdk group with 2 updates ([#44](https://github.com/fitbeard/radosgw-assume/issues/44)) ([48f6af7](https://github.com/fitbeard/radosgw-assume/commit/48f6af7e4df7f04668153be74731969a7b97ae76))
* **deps:** Bump the aws-sdk group with 2 updates ([#46](https://github.com/fitbeard/radosgw-assume/issues/46)) ([1a42159](https://github.com/fitbeard/radosgw-assume/commit/1a42159ad3fcf821c8f3d3958e3fd304e9bbce01))
* **deps:** Bump the aws-sdk group with 2 updates ([#48](https://github.com/fitbeard/radosgw-assume/issues/48)) ([cda87a4](https://github.com/fitbeard/radosgw-assume/commit/cda87a4710c6f24a4f120e17fad792b30fa1665f))
* **deps:** Bump the aws-sdk group with 2 updates ([#53](https://github.com/fitbeard/radosgw-assume/issues/53)) ([a110a4c](https://github.com/fitbeard/radosgw-assume/commit/a110a4cd3fcc6a0d2952150a77a71b7d5021fb18))
* **deps:** Bump the aws-sdk group with 2 updates ([#57](https://github.com/fitbeard/radosgw-assume/issues/57)) ([fa5d301](https://github.com/fitbeard/radosgw-assume/commit/fa5d301154ff6a86425cc56a4ee07d3018186b5f))
* improve release please config ([#10](https://github.com/fitbeard/radosgw-assume/issues/10)) ([8c3ea7e](https://github.com/fitbeard/radosgw-assume/commit/8c3ea7e84194a2e345dab870f1c4df0cc071df8b))
* **main:** release 1.0.0 ([38f3883](https://github.com/fitbeard/radosgw-assume/commit/38f38838c1307d7df26dc84ac602010f5fa5545d))
* **main:** release 1.0.0 ([2503063](https://github.com/fitbeard/radosgw-assume/commit/2503063f3d3354ae940d104316d6d453c7259ab4))
* **main:** release 1.1.0 ([#11](https://github.com/fitbeard/radosgw-assume/issues/11)) ([6805912](https://github.com/fitbeard/radosgw-assume/commit/68059126092baba4dfc420043623fec8ad8b6b56))
* **main:** release 1.2.0 ([#14](https://github.com/fitbeard/radosgw-assume/issues/14)) ([23a60c7](https://github.com/fitbeard/radosgw-assume/commit/23a60c7ca8f653d35980e307b8dd59b437b30809))
* **main:** release 1.3.0 ([#16](https://github.com/fitbeard/radosgw-assume/issues/16)) ([b82280f](https://github.com/fitbeard/radosgw-assume/commit/b82280fcdde27ecb096199639988126b2a1ec2a5))
* **main:** release 1.4.0 ([#26](https://github.com/fitbeard/radosgw-assume/issues/26)) ([aa3a628](https://github.com/fitbeard/radosgw-assume/commit/aa3a628fc048ce49060c6bf395d81dc99ab784ce))
* **main:** release 1.4.1 ([#34](https://github.com/fitbeard/radosgw-assume/issues/34)) ([24ccdec](https://github.com/fitbeard/radosgw-assume/commit/24ccdecf92ce3847af4e2c2466e6580dc693518f))
* **main:** release 1.4.2 ([#36](https://github.com/fitbeard/radosgw-assume/issues/36)) ([7f08cfa](https://github.com/fitbeard/radosgw-assume/commit/7f08cfa39d89b3b019ec5e65786f60b684e4e48e))
* **main:** release 1.4.3 ([#43](https://github.com/fitbeard/radosgw-assume/issues/43)) ([ef143b0](https://github.com/fitbeard/radosgw-assume/commit/ef143b0dad251ead661a0d3010209cefc7702810))
* **main:** release 1.4.4 ([#50](https://github.com/fitbeard/radosgw-assume/issues/50)) ([8883f08](https://github.com/fitbeard/radosgw-assume/commit/8883f08f5130569c43590e467e0c28e44d98d616))
* **main:** release 1.5.0 ([#59](https://github.com/fitbeard/radosgw-assume/issues/59)) ([0aa074a](https://github.com/fitbeard/radosgw-assume/commit/0aa074af4418a13bfed7e3a5e181733e0fbaa1c4))
* **main:** release 2.0.0 ([#73](https://github.com/fitbeard/radosgw-assume/issues/73)) ([8852e62](https://github.com/fitbeard/radosgw-assume/commit/8852e621011afc20f688361ff01495a826f0108c))
* update README ([#17](https://github.com/fitbeard/radosgw-assume/issues/17)) ([fda3c5c](https://github.com/fitbeard/radosgw-assume/commit/fda3c5ce55a23da08f233105c38bce04ddaeb299))
* update release configuration ([#32](https://github.com/fitbeard/radosgw-assume/issues/32)) ([cc3ea36](https://github.com/fitbeard/radosgw-assume/commit/cc3ea36d2c81370a4ea3973b4f416603b9f78a7e))

## [2.0.0](https://github.com/fitbeard/radosgw-assume/compare/v1.5.0...v2.0.0) (2026-08-18)


### ⚠ BREAKING CHANGES

* require profile selection through flag ([#76](https://github.com/fitbeard/radosgw-assume/issues/76))

### Features

* add authenticated shell command ([#80](https://github.com/fitbeard/radosgw-assume/issues/80)) ([0b7f8c8](https://github.com/fitbeard/radosgw-assume/commit/0b7f8c843b68ce32a104e100e2824c50b53c03e7))
* add AWS credential_process command ([#87](https://github.com/fitbeard/radosgw-assume/issues/87)) ([1a3bd1b](https://github.com/fitbeard/radosgw-assume/commit/1a3bd1bbf2e40cfa3ea4116c2c00e75bfa87e9d8))
* add core performance baselines ([#110](https://github.com/fitbeard/radosgw-assume/issues/110)) ([39b10aa](https://github.com/fitbeard/radosgw-assume/commit/39b10aafb715d5f9d15b37609fec1385795c4465))
* add credential cache management ([#90](https://github.com/fitbeard/radosgw-assume/issues/90)) ([a9cd597](https://github.com/fitbeard/radosgw-assume/commit/a9cd597f19a86a02d5ed26da080e0c5b4efbc05a))
* add exec command ([#79](https://github.com/fitbeard/radosgw-assume/issues/79)) ([08d7ea4](https://github.com/fitbeard/radosgw-assume/commit/08d7ea4fb59b40183d3cb092996ec92f928a7fac))
* cache credential_process credentials securely ([#88](https://github.com/fitbeard/radosgw-assume/issues/88)) ([2c328a8](https://github.com/fitbeard/radosgw-assume/commit/2c328a8482aea4cf11c5ffbb43d2af5f23b04e90))
* centralize HTTP client construction ([#82](https://github.com/fitbeard/radosgw-assume/issues/82)) ([25901c4](https://github.com/fitbeard/radosgw-assume/commit/25901c4120d230a8fdd984ca3b98021d494e1587))
* consolidate OIDC token handling ([#83](https://github.com/fitbeard/radosgw-assume/issues/83)) ([1d8d741](https://github.com/fitbeard/radosgw-assume/commit/1d8d741624113c2043ba451b42349c2448cd8fc6))
* discover OIDC provider endpoints ([#84](https://github.com/fitbeard/radosgw-assume/issues/84)) ([309e3ee](https://github.com/fitbeard/radosgw-assume/commit/309e3ee62e1921737e527c8b67031c6e38001354))
* require profile selection through flag ([#76](https://github.com/fitbeard/radosgw-assume/issues/76)) ([646aae8](https://github.com/fitbeard/radosgw-assume/commit/646aae846fc1f3b21875f2c42914014da6c02a17))
* separate authenticated shell components ([#97](https://github.com/fitbeard/radosgw-assume/issues/97)) ([68d52b6](https://github.com/fitbeard/radosgw-assume/commit/68d52b613d6d402adf692e3243cbd1a2930be7e3))
* separate browser authentication components ([#95](https://github.com/fitbeard/radosgw-assume/issues/95)) ([51ca6a6](https://github.com/fitbeard/radosgw-assume/commit/51ca6a6bdf0cc2c390e238986f8347f490cbbdb0))
* separate CLI action execution ([#94](https://github.com/fitbeard/radosgw-assume/issues/94)) ([3c093cf](https://github.com/fitbeard/radosgw-assume/commit/3c093cf3e720c26e9416be1bb1936fa2f406a6b8))
* separate configuration loading and resolution ([#99](https://github.com/fitbeard/radosgw-assume/issues/99)) ([3280dd9](https://github.com/fitbeard/radosgw-assume/commit/3280dd9e8873e544c88108ee1421e9457eacb69e))
* separate credential cache components ([#98](https://github.com/fitbeard/radosgw-assume/issues/98)) ([2568227](https://github.com/fitbeard/radosgw-assume/commit/2568227b532d50c8cde1a5b183aabedf4fa9da2e))
* separate credential orchestration components ([#100](https://github.com/fitbeard/radosgw-assume/issues/100)) ([c51265e](https://github.com/fitbeard/radosgw-assume/commit/c51265e5676437da886600aae792afd37dba6359))
* separate device authentication components ([#102](https://github.com/fitbeard/radosgw-assume/issues/102)) ([978bc8c](https://github.com/fitbeard/radosgw-assume/commit/978bc8c65a16461604908bbf38f2a94e52a508b5))
* separate device authentication components ([#103](https://github.com/fitbeard/radosgw-assume/issues/103)) ([4864418](https://github.com/fitbeard/radosgw-assume/commit/4864418122810510dbf39019a1c375a19cae2f5b))
* separate OIDC authentication helpers ([#96](https://github.com/fitbeard/radosgw-assume/issues/96)) ([5a411ac](https://github.com/fitbeard/radosgw-assume/commit/5a411ac6dadf26bd2b27149a7f64606ee824a73f))
* separate STS request and error handling ([#101](https://github.com/fitbeard/radosgw-assume/issues/101)) ([ad25cfc](https://github.com/fitbeard/radosgw-assume/commit/ad25cfcb205c132a5ea5020e1d37af52ac3d72b4))
* simplify browser authentication orchestration ([#108](https://github.com/fitbeard/radosgw-assume/issues/108)) ([26dd4b7](https://github.com/fitbeard/radosgw-assume/commit/26dd4b7d30ebd24d36c4319ff30f0780b41f90ff))
* use typed credential request options ([#107](https://github.com/fitbeard/radosgw-assume/issues/107)) ([142fffe](https://github.com/fitbeard/radosgw-assume/commit/142fffef8cc47692c3a6e604c2d62d6d1de18ba3))
* use typed OIDC authentication options ([#105](https://github.com/fitbeard/radosgw-assume/issues/105)) ([8c27c28](https://github.com/fitbeard/radosgw-assume/commit/8c27c287664153c3cd1744f55022fd2f57ca556f))
* use typed STS assume-role options ([#106](https://github.com/fitbeard/radosgw-assume/issues/106)) ([1dbdae2](https://github.com/fitbeard/radosgw-assume/commit/1dbdae24075085fed4ab4791d5e0746e4f82acf3))


### Bug Fixes

* harden network error handling ([#78](https://github.com/fitbeard/radosgw-assume/issues/78)) ([c7839fd](https://github.com/fitbeard/radosgw-assume/commit/c7839fd145ffc3408c877d58c97695f32c44f270))
* harden OIDC response handling ([#77](https://github.com/fitbeard/radosgw-assume/issues/77)) ([180bc6d](https://github.com/fitbeard/radosgw-assume/commit/180bc6db4c7f20b1f9758f3b31cfeee2e7926c6a))
* harden source profile resolution ([#75](https://github.com/fitbeard/radosgw-assume/issues/75)) ([ac40c6e](https://github.com/fitbeard/radosgw-assume/commit/ac40c6eed6173f12fdf9802872d74dbd547684af))
* honor OIDC device authorization expiry ([#91](https://github.com/fitbeard/radosgw-assume/issues/91)) ([7023795](https://github.com/fitbeard/radosgw-assume/commit/7023795c485a2fa8be9e48c7012f8184b5d2838b))
* improve secure random string generation ([#81](https://github.com/fitbeard/radosgw-assume/issues/81)) ([d93ee78](https://github.com/fitbeard/radosgw-assume/commit/d93ee78d951293aaf821bc76d57a7d5b0dda408b))
* prevent accidental credential output to terminal ([#109](https://github.com/fitbeard/radosgw-assume/issues/109)) ([c5d6221](https://github.com/fitbeard/radosgw-assume/commit/c5d6221c14dd6329546b0cda5c7e8d57339ade95))
* propagate context through authentication requests ([#93](https://github.com/fitbeard/radosgw-assume/issues/93)) ([a2e306c](https://github.com/fitbeard/radosgw-assume/commit/a2e306c5bbade5abba0b384190ffff638a7e3e81))
* remove obsolete configuration APIs ([#85](https://github.com/fitbeard/radosgw-assume/issues/85)) ([044f322](https://github.com/fitbeard/radosgw-assume/commit/044f3221c50ea8f298a8b25d13fbc7c1f8848079))
* separate command argument parsing ([#92](https://github.com/fitbeard/radosgw-assume/issues/92)) ([8ef91de](https://github.com/fitbeard/radosgw-assume/commit/8ef91dec1e0dc03d78201e16cd35bb82754d1fa0))
* support interactive exports through source ([#86](https://github.com/fitbeard/radosgw-assume/issues/86)) ([3180c44](https://github.com/fitbeard/radosgw-assume/commit/3180c4463cd8c22541480ef6d65ac61c46486fa8))
* validate configuration values consistently ([#104](https://github.com/fitbeard/radosgw-assume/issues/104)) ([0aa6536](https://github.com/fitbeard/radosgw-assume/commit/0aa65361f4dccd1cc7da388f8b244d093ce0bb46))
* validate STS credential responses ([#74](https://github.com/fitbeard/radosgw-assume/issues/74)) ([6c68118](https://github.com/fitbeard/radosgw-assume/commit/6c681188043d08c1791fee9e04b2d541fe47af50))


### Miscellaneous

* **deps:** Bump charm.land/lipgloss/v2 from 2.0.1 to 2.0.6 ([#89](https://github.com/fitbeard/radosgw-assume/issues/89)) ([3125d34](https://github.com/fitbeard/radosgw-assume/commit/3125d34feb366e53d43eae68398ba503b284a430))

## [1.5.0](https://github.com/fitbeard/radosgw-assume/compare/v1.4.4...v1.5.0) (2026-08-11)


### Features

* cleanup and switch to golang 1.26 ([#62](https://github.com/fitbeard/radosgw-assume/issues/62)) ([a663df8](https://github.com/fitbeard/radosgw-assume/commit/a663df8f33131ca4e71627a27c929b64d4c5da9e))
* make AWS config loading deterministic ([#71](https://github.com/fitbeard/radosgw-assume/issues/71)) ([ac06ffd](https://github.com/fitbeard/radosgw-assume/commit/ac06ffd68da2f3052cefaf9d9b0870759f490b6e))
* make browser authentication flow testable ([#68](https://github.com/fitbeard/radosgw-assume/issues/68)) ([7c1d8f4](https://github.com/fitbeard/radosgw-assume/commit/7c1d8f406d5943c80617bd7eb1a1fd903502eb52))
* make device authentication flow testable ([#69](https://github.com/fitbeard/radosgw-assume/issues/69)) ([024876e](https://github.com/fitbeard/radosgw-assume/commit/024876eebf7022598712bd29a658fca4526775a8))


### Bug Fixes

* bound OIDC and STS request durations ([#65](https://github.com/fitbeard/radosgw-assume/issues/65)) ([6a5bdd2](https://github.com/fitbeard/radosgw-assume/commit/6a5bdd2ad4bb3f29a4dc2bd65bebd95adf7cc297))
* close device polling responses promptly and set PKCE method for device auth ([#63](https://github.com/fitbeard/radosgw-assume/issues/63)) ([7cebbe2](https://github.com/fitbeard/radosgw-assume/commit/7cebbe2fd1b2a2f5c90ffd71b1f24ad2782f2a53))
* harden browser callback lifecycle ([#64](https://github.com/fitbeard/radosgw-assume/issues/64)) ([5054241](https://github.com/fitbeard/radosgw-assume/commit/50542416fa3d777b5214d5cfffdca7362460e822))
* make progress indicator shutdown idempotent ([#70](https://github.com/fitbeard/radosgw-assume/issues/70)) ([3fe03c4](https://github.com/fitbeard/radosgw-assume/commit/3fe03c4d84055222c8dc69bfa5610c8286958a70))


### Documentation

* fix AWS config keys in README ([#72](https://github.com/fitbeard/radosgw-assume/issues/72)) ([ea57a1f](https://github.com/fitbeard/radosgw-assume/commit/ea57a1f55bd4b7fd1e87ca982cec78d2e87bcaff))

## [1.4.4](https://github.com/fitbeard/radosgw-assume/compare/v1.4.3...v1.4.4) (2026-08-06)


### Miscellaneous

* **deps:** Bump actions/checkout from 6 to 7 ([#51](https://github.com/fitbeard/radosgw-assume/issues/51)) ([7b5499b](https://github.com/fitbeard/radosgw-assume/commit/7b5499bc80aad0ce0f315fc71ccd18ed30bd8406))
* **deps:** Bump actions/setup-go from 6 to 7 ([#55](https://github.com/fitbeard/radosgw-assume/issues/55)) ([1adc1da](https://github.com/fitbeard/radosgw-assume/commit/1adc1dafe026946b3aee90b43c31c49162ebba25))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#54](https://github.com/fitbeard/radosgw-assume/issues/54)) ([437fbfc](https://github.com/fitbeard/radosgw-assume/commit/437fbfc92fe8e6cae883f821311ada5b8dc0e8c6))
* **deps:** Bump github.com/aws/smithy-go from 1.27.3 to 1.27.4 ([#56](https://github.com/fitbeard/radosgw-assume/issues/56)) ([55af1c4](https://github.com/fitbeard/radosgw-assume/commit/55af1c48dff2bcaafe7b558ff13d2fcf50170bf7))
* **deps:** Bump github.com/aws/smithy-go from 1.27.4 to 1.27.6 ([#58](https://github.com/fitbeard/radosgw-assume/issues/58)) ([7ef4cdf](https://github.com/fitbeard/radosgw-assume/commit/7ef4cdfb1d6a76c04a982a408048cdbec88b80b0))
* **deps:** Bump the aws-sdk group with 2 updates ([#53](https://github.com/fitbeard/radosgw-assume/issues/53)) ([a110a4c](https://github.com/fitbeard/radosgw-assume/commit/a110a4cd3fcc6a0d2952150a77a71b7d5021fb18))
* **deps:** Bump the aws-sdk group with 2 updates ([#57](https://github.com/fitbeard/radosgw-assume/issues/57)) ([fa5d301](https://github.com/fitbeard/radosgw-assume/commit/fa5d301154ff6a86425cc56a4ee07d3018186b5f))

## [1.4.3](https://github.com/fitbeard/radosgw-assume/compare/v1.4.2...v1.4.3) (2026-06-17)


### Miscellaneous

* **deps:** Bump github.com/aws/smithy-go from 1.27.1 to 1.27.2 ([#47](https://github.com/fitbeard/radosgw-assume/issues/47)) ([5059e06](https://github.com/fitbeard/radosgw-assume/commit/5059e067b01a14fb8324bcf0ff16f8fe88e26d7b))
* **deps:** Bump gopkg.in/ini.v1 from 1.67.2 to 1.67.3 ([#49](https://github.com/fitbeard/radosgw-assume/issues/49)) ([12a1b0c](https://github.com/fitbeard/radosgw-assume/commit/12a1b0c35f66bb9b57659a371fb0dc6ba4476c3b))
* **deps:** Bump the aws-sdk group with 2 updates ([#44](https://github.com/fitbeard/radosgw-assume/issues/44)) ([48f6af7](https://github.com/fitbeard/radosgw-assume/commit/48f6af7e4df7f04668153be74731969a7b97ae76))
* **deps:** Bump the aws-sdk group with 2 updates ([#46](https://github.com/fitbeard/radosgw-assume/issues/46)) ([1a42159](https://github.com/fitbeard/radosgw-assume/commit/1a42159ad3fcf821c8f3d3958e3fd304e9bbce01))
* **deps:** Bump the aws-sdk group with 2 updates ([#48](https://github.com/fitbeard/radosgw-assume/issues/48)) ([cda87a4](https://github.com/fitbeard/radosgw-assume/commit/cda87a4710c6f24a4f120e17fad792b30fa1665f))

## [1.4.2](https://github.com/fitbeard/radosgw-assume/compare/v1.4.1...v1.4.2) (2026-05-06)


### Miscellaneous

* **deps:** Bump github.com/aws/smithy-go from 1.25.0 to 1.25.1 ([#39](https://github.com/fitbeard/radosgw-assume/issues/39)) ([1c01a48](https://github.com/fitbeard/radosgw-assume/commit/1c01a48bfd3db6f23805b0084fa576f25e36966a))
* **deps:** Bump googleapis/release-please-action from 4 to 5 ([#40](https://github.com/fitbeard/radosgw-assume/issues/40)) ([7d187eb](https://github.com/fitbeard/radosgw-assume/commit/7d187ebf5338444ab5e41ae53a9a091a1715c8b1))
* **deps:** Bump gopkg.in/ini.v1 from 1.67.1 to 1.67.2 ([#42](https://github.com/fitbeard/radosgw-assume/issues/42)) ([c9aca5d](https://github.com/fitbeard/radosgw-assume/commit/c9aca5d19dc6fa0ac04943dab158eaa2cc4a4231))
* **deps:** Bump the aws-sdk group with 2 updates ([#37](https://github.com/fitbeard/radosgw-assume/issues/37)) ([6fb6df5](https://github.com/fitbeard/radosgw-assume/commit/6fb6df5ca53a9e94c1619bc02c9aa9914d010267))
* **deps:** Bump the aws-sdk group with 2 updates ([#41](https://github.com/fitbeard/radosgw-assume/issues/41)) ([8f17a92](https://github.com/fitbeard/radosgw-assume/commit/8f17a922f01bd48fb858bf67ddcba89b57ea3a8f))

## [1.4.1](https://github.com/fitbeard/radosgw-assume/compare/v1.4.0...v1.4.1) (2026-04-14)


### Bug Fixes

* remove the quarantine bit from the binary on MacOS ([#35](https://github.com/fitbeard/radosgw-assume/issues/35)) ([55595c3](https://github.com/fitbeard/radosgw-assume/commit/55595c34410310f6d34d751d3e18d57f4cb78542))

## [1.4.0](https://github.com/fitbeard/radosgw-assume/compare/v1.3.0...v1.4.0) (2026-04-14)


### Features

* update release-please config ([#25](https://github.com/fitbeard/radosgw-assume/issues/25)) ([6e74d4b](https://github.com/fitbeard/radosgw-assume/commit/6e74d4bcdb231edf1b3005664878e915d6d67a2a))


### Miscellaneous

* **deps:** Bump github.com/aws/aws-sdk-go-v2 from 1.41.2 to 1.41.3 ([#24](https://github.com/fitbeard/radosgw-assume/issues/24)) ([ca646bf](https://github.com/fitbeard/radosgw-assume/commit/ca646bf4a58768d838e317b6fd5b8ec00f74d4c2))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#19](https://github.com/fitbeard/radosgw-assume/issues/19)) ([3cce704](https://github.com/fitbeard/radosgw-assume/commit/3cce7040b16f1a3740c3382b6752a84375ae854f))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#22](https://github.com/fitbeard/radosgw-assume/issues/22)) ([5346d77](https://github.com/fitbeard/radosgw-assume/commit/5346d77b7c2334c83a4796a830e3db2111fe3bfb))
* **deps:** Bump github.com/aws/aws-sdk-go-v2/service/sts ([#28](https://github.com/fitbeard/radosgw-assume/issues/28)) ([6eeedba](https://github.com/fitbeard/radosgw-assume/commit/6eeedba646596537dced0e822acf84109cf84a26))
* **deps:** Bump github.com/aws/smithy-go from 1.24.2 to 1.24.3 ([#31](https://github.com/fitbeard/radosgw-assume/issues/31)) ([2f0cf95](https://github.com/fitbeard/radosgw-assume/commit/2f0cf95406a806e225f07ccb991fc0c276a99279))
* **deps:** Bump goreleaser/goreleaser-action from 6 to 7 ([#18](https://github.com/fitbeard/radosgw-assume/issues/18)) ([b06475b](https://github.com/fitbeard/radosgw-assume/commit/b06475bbd8d7cb979ca4646cf328d8231fa2eea9))
* **deps:** Bump the aws-sdk group with 2 updates ([#33](https://github.com/fitbeard/radosgw-assume/issues/33)) ([ab395c9](https://github.com/fitbeard/radosgw-assume/commit/ab395c9df9109028eb0f6be1e4df357eef35c196))
* update README ([#17](https://github.com/fitbeard/radosgw-assume/issues/17)) ([fda3c5c](https://github.com/fitbeard/radosgw-assume/commit/fda3c5ce55a23da08f233105c38bce04ddaeb299))
* update release configuration ([#32](https://github.com/fitbeard/radosgw-assume/issues/32)) ([cc3ea36](https://github.com/fitbeard/radosgw-assume/commit/cc3ea36d2c81370a4ea3973b4f416603b9f78a7e))

## [1.3.0](https://github.com/fitbeard/radosgw-assume/compare/v1.2.0...v1.3.0) (2026-02-10)


### Features

* add brew release ([4ab6fc3](https://github.com/fitbeard/radosgw-assume/commit/4ab6fc3486fd58644c7dc583e82ca0e015f41860))

## [1.2.0](https://github.com/fitbeard/radosgw-assume/compare/v1.1.0...v1.2.0) (2026-01-30)


### Features

* add custom role_session_name option ([bcab432](https://github.com/fitbeard/radosgw-assume/commit/bcab4323298628b5cd9e0aff67aa2887012625dd))

## [1.1.0](https://github.com/fitbeard/radosgw-assume/compare/v1.0.0...v1.1.0) (2026-01-27)


### Features

* add kubernetes examples ([483afe5](https://github.com/fitbeard/radosgw-assume/commit/483afe5249db0e00b5a15b02094ae60d1abfdf43))
* add kubernetes examples ([211b6db](https://github.com/fitbeard/radosgw-assume/commit/211b6dbc2391542750647f39fbd65e413b11ddc4))
* improve error handling messages ([#13](https://github.com/fitbeard/radosgw-assume/issues/13)) ([1bc42b5](https://github.com/fitbeard/radosgw-assume/commit/1bc42b52c63682494e4907af06a3077e2222bbee))


### Bug Fixes

* remove duplicated code ([#12](https://github.com/fitbeard/radosgw-assume/issues/12)) ([daf134e](https://github.com/fitbeard/radosgw-assume/commit/daf134e272d9019c051d54033a21c936e41993a6))

## 1.0.0 (2025-12-11)


### Features

* Add documentation and examples ([bb58272](https://github.com/fitbeard/radosgw-assume/commit/bb58272d3f2348126c512c19a2bad00f9e9ce465))
* Add documentation and examples ([6a34c62](https://github.com/fitbeard/radosgw-assume/commit/6a34c62f5949f77c8990a57ff8556421ab172ecd))


### Bug Fixes

* naming pattern ([f6ea0f4](https://github.com/fitbeard/radosgw-assume/commit/f6ea0f48c97bc0265f7206f6a0f16734f22eb62c))
