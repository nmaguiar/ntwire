# image-ntwire-relay-linux-arm64 — linux/arm64

- Scanned: 2026-10-27 02:35 UTC
- Source commit: `66fde4fc6548754d54f45f2e95bd53b8d8a942da`
- Artifact: `nmaguiar/ntwire-relay@sha256:cb5cd20f9cc35b9b3fd219cfd8949bd03380e8d81d3c95b789e35a5010cb505b`
- Scanner: Trivy

CRITICAL: 0 | HIGH: 0 | MEDIUM: 0 | LOW: 0 | UNKNOWN: 4

| Advisory | Severity | Package | Installed | Fixed |
| --- | --- | --- | --- | --- |
| DLA-4845-1 | UNKNOWN | ca-certificates | 20250419~deb12u1 | 20250419~deb12u2 |
| DLA-4792-1 | UNKNOWN | tzdata | 2026b-0+deb12u1 | 2026c-0+deb12u1 |
| DLA-4854-1 | UNKNOWN | tzdata | 2026b-0+deb12u1 | 2026e-0+deb12u1 |
| GO-2026-5932 | UNKNOWN | golang.org/x/crypto | v0.58.0 |  |

<details><summary>Full scanner output</summary>

```json
{
  "SchemaVersion": 2,
  "Trivy": {
    "Version": "0.76.1"
  },
  "ReportID": "01a17b36-8d9f-747b-8736-e414fd6b7b21",
  "CreatedAt": "2026-10-27T02:35:35.199295028Z",
  "ArtifactID": "sha256:737098e7b89e004fa979c0af93d30333ee2473a54943c32c2dd34f83b54211c2",
  "ArtifactName": "nmaguiar/ntwire-relay@sha256:cb5cd20f9cc35b9b3fd219cfd8949bd03380e8d81d3c95b789e35a5010cb505b",
  "ArtifactType": "container_image",
  "Metadata": {
    "Size": 34770432,
    "OS": {
      "Family": "debian",
      "Name": "12.15"
    },
    "ImageID": "sha256:5a3132e517eb717b8b409a2f0fc979000ff8ac67e7f73a092deb7deaf8d5b325",
    "DiffIDs": [
      "sha256:6fc9269a8b4d61cdd276e80d170e4caa1566efc1b9f42442fdad4f69836b3c4f",
      "sha256:8fa10c0194df9b7c054c90dbe482585f768a54428fc90a5b78a0066a123b1bba",
      "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710",
      "sha256:114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9",
      "sha256:4d049f83d9cf21d1f5cc0e11deaf36df02790d0e60c1a3829538fb4b61685368",
      "sha256:af5aa97ebe6ce1604747ec1e21af7136ded391bcabe4acef882e718a87c86bcc",
      "sha256:6f1cdceb6a3146f0ccb986521156bef8a422cdbb0863396f7f751f575ba308f4",
      "sha256:bd3cdfae1d3fdd83a2231d608969b38b82349777c2fff9a7c12d54f8ac5c9b38",
      "sha256:4cde6b0bb6f50a5f255eef7b2a42162c661cf776b803225dcac9a659e396bb6b",
      "sha256:ad51d0769d16ba578106a177987dfe3d2e02c1668c852b795b2f6b024068242a",
      "sha256:6e7fbcf090d09b73a4aa85f9dce690d0ace73877c150b7c56955487b6e7a822a",
      "sha256:5904c32f457c96a16c8c68f5ccdf518c8138cd9e5971de9ce6d564fc481af222",
      "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
    ],
    "RepoDigests": [
      "nmaguiar/ntwire-relay@sha256:cb5cd20f9cc35b9b3fd219cfd8949bd03380e8d81d3c95b789e35a5010cb505b"
    ],
    "Reference": "nmaguiar/ntwire-relay@sha256:cb5cd20f9cc35b9b3fd219cfd8949bd03380e8d81d3c95b789e35a5010cb505b",
    "ImageConfig": {
      "architecture": "arm64",
      "created": "2026-10-27T02:34:12.409523693Z",
      "history": [
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build @bookworm//base-files/arm64:data_statusd"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build @bookworm//netbase/arm64:data_statusd"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build @bookworm//tzdata/arm64:data_statusd"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build @bookworm//media-types/arm64:data_statusd"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:rootfs"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:passwd"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:home"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:group"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:tmp"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //static:nsswitch"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:os_release_debian12"
        },
        {
          "created": "1970-01-01T00:00:00Z",
          "created_by": "bazel build //common:cacerts_debian12_arm64_tar"
        },
        {
          "created": "2026-10-27T02:34:12.409523693Z",
          "created_by": "COPY /out/ntwire-relay /ntwire-relay # buildkit",
          "comment": "buildkit.dockerfile.v0"
        },
        {
          "created": "2026-10-27T02:34:12.409523693Z",
          "created_by": "USER nonroot:nonroot",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2026-10-27T02:34:12.409523693Z",
          "created_by": "ENV NTWIRE_LOG_FORMAT=json",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        },
        {
          "created": "2026-10-27T02:34:12.409523693Z",
          "created_by": "ENTRYPOINT [\"/ntwire-relay\"]",
          "comment": "buildkit.dockerfile.v0",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:6fc9269a8b4d61cdd276e80d170e4caa1566efc1b9f42442fdad4f69836b3c4f",
          "sha256:8fa10c0194df9b7c054c90dbe482585f768a54428fc90a5b78a0066a123b1bba",
          "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710",
          "sha256:114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9",
          "sha256:4d049f83d9cf21d1f5cc0e11deaf36df02790d0e60c1a3829538fb4b61685368",
          "sha256:af5aa97ebe6ce1604747ec1e21af7136ded391bcabe4acef882e718a87c86bcc",
          "sha256:6f1cdceb6a3146f0ccb986521156bef8a422cdbb0863396f7f751f575ba308f4",
          "sha256:bd3cdfae1d3fdd83a2231d608969b38b82349777c2fff9a7c12d54f8ac5c9b38",
          "sha256:4cde6b0bb6f50a5f255eef7b2a42162c661cf776b803225dcac9a659e396bb6b",
          "sha256:ad51d0769d16ba578106a177987dfe3d2e02c1668c852b795b2f6b024068242a",
          "sha256:6e7fbcf090d09b73a4aa85f9dce690d0ace73877c150b7c56955487b6e7a822a",
          "sha256:5904c32f457c96a16c8c68f5ccdf518c8138cd9e5971de9ce6d564fc481af222",
          "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
        ]
      },
      "config": {
        "Entrypoint": [
          "/ntwire-relay"
        ],
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
          "NTWIRE_LOG_FORMAT=json"
        ],
        "User": "nonroot:nonroot",
        "WorkingDir": "/home/nonroot"
      }
    },
    "Layers": [
      {
        "Size": 327680,
        "Digest": "sha256:f7c03e5221c3717bfa68250498f74132c03d9d7271f301c9b2a9cfc00fc6e231",
        "DiffID": "sha256:6fc9269a8b4d61cdd276e80d170e4caa1566efc1b9f42442fdad4f69836b3c4f"
      },
      {
        "Size": 40960,
        "Digest": "sha256:990a9c434e5e0f11549a8d4a41a1991e621b04e30cd63269adbc97b1dc38fd7e",
        "DiffID": "sha256:8fa10c0194df9b7c054c90dbe482585f768a54428fc90a5b78a0066a123b1bba"
      },
      {
        "Size": 2416640,
        "Digest": "sha256:39dc083afc39bd8dc43d456fe7ff7d39292e593bb2769972c11bb2e5f9119386",
        "DiffID": "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710"
      },
      {
        "Size": 102400,
        "Digest": "sha256:bf7a4185f01524837d19abde915ffde84e64368b250f5b5e9f6f75aea62a11d4",
        "DiffID": "sha256:114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9"
      },
      {
        "Size": 1536,
        "Digest": "sha256:2780920e5dbfbe103d03a583ed75345306e572ec5a48cb10361f046767d9f29a",
        "DiffID": "sha256:4d049f83d9cf21d1f5cc0e11deaf36df02790d0e60c1a3829538fb4b61685368"
      },
      {
        "Size": 2560,
        "Digest": "sha256:7c12895b777bcaa8ccae0605b4de635b68fc32d60fa08f421dc3818bf55ee212",
        "DiffID": "sha256:af5aa97ebe6ce1604747ec1e21af7136ded391bcabe4acef882e718a87c86bcc"
      },
      {
        "Size": 2560,
        "Digest": "sha256:3214acf345c0cc6bbdb56b698a41ccdefc624a09d6beb0d38b5de0b2303ecaf4",
        "DiffID": "sha256:6f1cdceb6a3146f0ccb986521156bef8a422cdbb0863396f7f751f575ba308f4"
      },
      {
        "Size": 2560,
        "Digest": "sha256:52630fc75a18675c530ed9eba5f55eca09b03e91bd5bc15307918bbc1a7e7296",
        "DiffID": "sha256:bd3cdfae1d3fdd83a2231d608969b38b82349777c2fff9a7c12d54f8ac5c9b38"
      },
      {
        "Size": 1536,
        "Digest": "sha256:dd64bf2dd177757451a98fcdc999a339c35dee5d9872d8f4dc69c8f3c4dd0112",
        "DiffID": "sha256:4cde6b0bb6f50a5f255eef7b2a42162c661cf776b803225dcac9a659e396bb6b"
      },
      {
        "Size": 2048,
        "Digest": "sha256:b839dfae01f66e15c6a8b63520557ed315bdfe036342fa7a0c537259f10d7a9a",
        "DiffID": "sha256:ad51d0769d16ba578106a177987dfe3d2e02c1668c852b795b2f6b024068242a"
      },
      {
        "Size": 3072,
        "Digest": "sha256:dcaa5a89b0ccda4b283e16d0b4d0891cd93d5fe05c6798f7806781a6a2d84354",
        "DiffID": "sha256:6e7fbcf090d09b73a4aa85f9dce690d0ace73877c150b7c56955487b6e7a822a"
      },
      {
        "Size": 276480,
        "Digest": "sha256:4db96f2c7ae9e90f3fd5e91cf947d19cced1d8a778d12923113f62c7fff3ec3e",
        "DiffID": "sha256:5904c32f457c96a16c8c68f5ccdf518c8138cd9e5971de9ce6d564fc481af222"
      },
      {
        "Size": 31590400,
        "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
        "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
      }
    ]
  },
  "Results": [
    {
      "Target": "nmaguiar/ntwire-relay@sha256:cb5cd20f9cc35b9b3fd219cfd8949bd03380e8d81d3c95b789e35a5010cb505b (debian 12.15)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [
        {
          "ID": "base-files@12.4+deb12u15",
          "Name": "base-files",
          "Identifier": {
            "PURL": "pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=arm64\u0026distro=debian-12.15",
            "UID": "5ab39d68583fc7fa"
          },
          "Version": "12.4+deb12u15",
          "Arch": "arm64",
          "SrcName": "base-files",
          "SrcVersion": "12.4+deb12u15",
          "Licenses": [
            "GPL-2.0-or-later"
          ],
          "Maintainer": "Santiago Vila \u003csanvila@debian.org\u003e",
          "Repository": {
            "Class": "official"
          },
          "Layer": {
            "Digest": "sha256:f7c03e5221c3717bfa68250498f74132c03d9d7271f301c9b2a9cfc00fc6e231",
            "DiffID": "sha256:6fc9269a8b4d61cdd276e80d170e4caa1566efc1b9f42442fdad4f69836b3c4f"
          },
          "InstalledFiles": [
            "/usr/lib/os-release",
            "/usr/share/base-files/dot.bashrc",
            "/usr/share/base-files/dot.profile",
            "/usr/share/base-files/dot.profile.md5sums",
            "/usr/share/base-files/info.dir",
            "/usr/share/base-files/motd",
            "/usr/share/base-files/profile",
            "/usr/share/base-files/profile.md5sums",
            "/usr/share/base-files/staff-group-for-usr-local",
            "/usr/share/common-licenses/Apache-2.0",
            "/usr/share/common-licenses/Artistic",
            "/usr/share/common-licenses/BSD",
            "/usr/share/common-licenses/CC0-1.0",
            "/usr/share/common-licenses/GFDL-1.2",
            "/usr/share/common-licenses/GFDL-1.3",
            "/usr/share/common-licenses/GPL-1",
            "/usr/share/common-licenses/GPL-2",
            "/usr/share/common-licenses/GPL-3",
            "/usr/share/common-licenses/LGPL-2",
            "/usr/share/common-licenses/LGPL-2.1",
            "/usr/share/common-licenses/LGPL-3",
            "/usr/share/common-licenses/MPL-1.1",
            "/usr/share/common-licenses/MPL-2.0",
            "/usr/share/doc/base-files/README",
            "/usr/share/doc/base-files/README.FHS",
            "/usr/share/doc/base-files/changelog.gz",
            "/usr/share/doc/base-files/copyright",
            "/usr/share/lintian/overrides/base-files"
          ],
          "AnalyzedBy": "dpkg"
        },
        {
          "ID": "ca-certificates@20250419~deb12u1",
          "Name": "ca-certificates",
          "Identifier": {
            "PURL": "pkg:deb/debian/ca-certificates@20250419~deb12u1?arch=all\u0026distro=debian-12.15",
            "UID": "8dc50e3eef6bbc7d"
          },
          "Version": "20250419~deb12u1",
          "Arch": "all",
          "SrcName": "ca-certificates",
          "SrcVersion": "20250419~deb12u1",
          "Licenses": [
            "GPL-2.0-or-later",
            "GPL-2.0-only",
            "MPL-2.0"
          ],
          "Maintainer": "Julien Cristau \u003cjcristau@debian.org\u003e",
          "Repository": {
            "Class": "official"
          },
          "Layer": {
            "Digest": "sha256:4db96f2c7ae9e90f3fd5e91cf947d19cced1d8a778d12923113f62c7fff3ec3e",
            "DiffID": "sha256:5904c32f457c96a16c8c68f5ccdf518c8138cd9e5971de9ce6d564fc481af222"
          },
          "InstalledFiles": [
            "/usr/sbin/update-ca-certificates",
            "/usr/share/ca-certificates/mozilla/ACCVRAIZ1.crt",
            "/usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM.crt",
            "/usr/share/ca-certificates/mozilla/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt",
            "/usr/share/ca-certificates/mozilla/ANF_Secure_Server_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/Actalis_Authentication_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/AffirmTrust_Commercial.crt",
            "/usr/share/ca-certificates/mozilla/AffirmTrust_Networking.crt",
            "/usr/share/ca-certificates/mozilla/AffirmTrust_Premium.crt",
            "/usr/share/ca-certificates/mozilla/AffirmTrust_Premium_ECC.crt",
            "/usr/share/ca-certificates/mozilla/Amazon_Root_CA_1.crt",
            "/usr/share/ca-certificates/mozilla/Amazon_Root_CA_2.crt",
            "/usr/share/ca-certificates/mozilla/Amazon_Root_CA_3.crt",
            "/usr/share/ca-certificates/mozilla/Amazon_Root_CA_4.crt",
            "/usr/share/ca-certificates/mozilla/Atos_TrustedRoot_2011.crt",
            "/usr/share/ca-certificates/mozilla/Atos_TrustedRoot_Root_CA_ECC_TLS_2021.crt",
            "/usr/share/ca-certificates/mozilla/Atos_TrustedRoot_Root_CA_RSA_TLS_2021.crt",
            "/usr/share/ca-certificates/mozilla/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt",
            "/usr/share/ca-certificates/mozilla/BJCA_Global_Root_CA1.crt",
            "/usr/share/ca-certificates/mozilla/BJCA_Global_Root_CA2.crt",
            "/usr/share/ca-certificates/mozilla/Baltimore_CyberTrust_Root.crt",
            "/usr/share/ca-certificates/mozilla/Buypass_Class_2_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/Buypass_Class_3_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/CA_Disig_Root_R2.crt",
            "/usr/share/ca-certificates/mozilla/CFCA_EV_ROOT.crt",
            "/usr/share/ca-certificates/mozilla/COMODO_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/COMODO_ECC_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/COMODO_RSA_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/Certainly_Root_E1.crt",
            "/usr/share/ca-certificates/mozilla/Certainly_Root_R1.crt",
            "/usr/share/ca-certificates/mozilla/Certigna.crt",
            "/usr/share/ca-certificates/mozilla/Certigna_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/Certum_EC-384_CA.crt",
            "/usr/share/ca-certificates/mozilla/Certum_Trusted_Network_CA.crt",
            "/usr/share/ca-certificates/mozilla/Certum_Trusted_Network_CA_2.crt",
            "/usr/share/ca-certificates/mozilla/Certum_Trusted_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/CommScope_Public_Trust_ECC_Root-01.crt",
            "/usr/share/ca-certificates/mozilla/CommScope_Public_Trust_ECC_Root-02.crt",
            "/usr/share/ca-certificates/mozilla/CommScope_Public_Trust_RSA_Root-01.crt",
            "/usr/share/ca-certificates/mozilla/CommScope_Public_Trust_RSA_Root-02.crt",
            "/usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_BR_Root_CA_1_2020.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_BR_Root_CA_2_2023.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_EV_Root_CA_1_2020.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_EV_Root_CA_2_2023.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_Root_Class_3_CA_2_2009.crt",
            "/usr/share/ca-certificates/mozilla/D-TRUST_Root_Class_3_CA_2_EV_2009.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Assured_ID_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Assured_ID_Root_G2.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Assured_ID_Root_G3.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Global_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Global_Root_G2.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Global_Root_G3.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_High_Assurance_EV_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_TLS_ECC_P384_Root_G5.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_TLS_RSA4096_Root_G5.crt",
            "/usr/share/ca-certificates/mozilla/DigiCert_Trusted_Root_G4.crt",
            "/usr/share/ca-certificates/mozilla/Entrust.net_Premium_2048_Secure_Server_CA.crt",
            "/usr/share/ca-certificates/mozilla/Entrust_Root_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/Entrust_Root_Certification_Authority_-_EC1.crt",
            "/usr/share/ca-certificates/mozilla/Entrust_Root_Certification_Authority_-_G2.crt",
            "/usr/share/ca-certificates/mozilla/FIRMAPROFESIONAL_CA_ROOT-A_WEB.crt",
            "/usr/share/ca-certificates/mozilla/GDCA_TrustAUTH_R5_ROOT.crt",
            "/usr/share/ca-certificates/mozilla/GLOBALTRUST_2020.crt",
            "/usr/share/ca-certificates/mozilla/GTS_Root_R1.crt",
            "/usr/share/ca-certificates/mozilla/GTS_Root_R2.crt",
            "/usr/share/ca-certificates/mozilla/GTS_Root_R3.crt",
            "/usr/share/ca-certificates/mozilla/GTS_Root_R4.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_ECC_Root_CA_-_R4.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_ECC_Root_CA_-_R5.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_Root_CA_-_R3.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_Root_CA_-_R6.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_Root_E46.crt",
            "/usr/share/ca-certificates/mozilla/GlobalSign_Root_R46.crt",
            "/usr/share/ca-certificates/mozilla/Go_Daddy_Class_2_CA.crt",
            "/usr/share/ca-certificates/mozilla/Go_Daddy_Root_Certificate_Authority_-_G2.crt",
            "/usr/share/ca-certificates/mozilla/HARICA_TLS_ECC_Root_CA_2021.crt",
            "/usr/share/ca-certificates/mozilla/HARICA_TLS_RSA_Root_CA_2021.crt",
            "/usr/share/ca-certificates/mozilla/Hellenic_Academic_and_Research_Institutions_ECC_RootCA_2015.crt",
            "/usr/share/ca-certificates/mozilla/Hellenic_Academic_and_Research_Institutions_RootCA_2015.crt",
            "/usr/share/ca-certificates/mozilla/HiPKI_Root_CA_-_G1.crt",
            "/usr/share/ca-certificates/mozilla/Hongkong_Post_Root_CA_3.crt",
            "/usr/share/ca-certificates/mozilla/ISRG_Root_X1.crt",
            "/usr/share/ca-certificates/mozilla/ISRG_Root_X2.crt",
            "/usr/share/ca-certificates/mozilla/IdenTrust_Commercial_Root_CA_1.crt",
            "/usr/share/ca-certificates/mozilla/IdenTrust_Public_Sector_Root_CA_1.crt",
            "/usr/share/ca-certificates/mozilla/Izenpe.com.crt",
            "/usr/share/ca-certificates/mozilla/Microsec_e-Szigno_Root_CA_2009.crt",
            "/usr/share/ca-certificates/mozilla/Microsoft_ECC_Root_Certificate_Authority_2017.crt",
            "/usr/share/ca-certificates/mozilla/Microsoft_RSA_Root_Certificate_Authority_2017.crt",
            "/usr/share/ca-certificates/mozilla/NAVER_Global_Root_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/NetLock_Arany_=Class_Gold=_Főtanúsítvány.crt",
            "/usr/share/ca-certificates/mozilla/OISTE_WISeKey_Global_Root_GB_CA.crt",
            "/usr/share/ca-certificates/mozilla/OISTE_WISeKey_Global_Root_GC_CA.crt",
            "/usr/share/ca-certificates/mozilla/QuoVadis_Root_CA_1_G3.crt",
            "/usr/share/ca-certificates/mozilla/QuoVadis_Root_CA_2.crt",
            "/usr/share/ca-certificates/mozilla/QuoVadis_Root_CA_2_G3.crt",
            "/usr/share/ca-certificates/mozilla/QuoVadis_Root_CA_3.crt",
            "/usr/share/ca-certificates/mozilla/QuoVadis_Root_CA_3_G3.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_EV_Root_Certification_Authority_ECC.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_EV_Root_Certification_Authority_RSA_R2.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_Root_Certification_Authority_ECC.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_Root_Certification_Authority_RSA.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_TLS_ECC_Root_CA_2022.crt",
            "/usr/share/ca-certificates/mozilla/SSL.com_TLS_RSA_Root_CA_2022.crt",
            "/usr/share/ca-certificates/mozilla/SZAFIR_ROOT_CA2.crt",
            "/usr/share/ca-certificates/mozilla/Sectigo_Public_Server_Authentication_Root_E46.crt",
            "/usr/share/ca-certificates/mozilla/Sectigo_Public_Server_Authentication_Root_R46.crt",
            "/usr/share/ca-certificates/mozilla/SecureSign_Root_CA12.crt",
            "/usr/share/ca-certificates/mozilla/SecureSign_Root_CA14.crt",
            "/usr/share/ca-certificates/mozilla/SecureSign_Root_CA15.crt",
            "/usr/share/ca-certificates/mozilla/SecureTrust_CA.crt",
            "/usr/share/ca-certificates/mozilla/Secure_Global_CA.crt",
            "/usr/share/ca-certificates/mozilla/Security_Communication_ECC_RootCA1.crt",
            "/usr/share/ca-certificates/mozilla/Security_Communication_RootCA2.crt",
            "/usr/share/ca-certificates/mozilla/Starfield_Class_2_CA.crt",
            "/usr/share/ca-certificates/mozilla/Starfield_Root_Certificate_Authority_-_G2.crt",
            "/usr/share/ca-certificates/mozilla/Starfield_Services_Root_Certificate_Authority_-_G2.crt",
            "/usr/share/ca-certificates/mozilla/SwissSign_Gold_CA_-_G2.crt",
            "/usr/share/ca-certificates/mozilla/T-TeleSec_GlobalRoot_Class_2.crt",
            "/usr/share/ca-certificates/mozilla/T-TeleSec_GlobalRoot_Class_3.crt",
            "/usr/share/ca-certificates/mozilla/TUBITAK_Kamu_SM_SSL_Kok_Sertifikasi_-_Surum_1.crt",
            "/usr/share/ca-certificates/mozilla/TWCA_CYBER_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/TWCA_Global_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/TWCA_Root_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/Telekom_Security_TLS_ECC_Root_2020.crt",
            "/usr/share/ca-certificates/mozilla/Telekom_Security_TLS_RSA_Root_2023.crt",
            "/usr/share/ca-certificates/mozilla/TeliaSonera_Root_CA_v1.crt",
            "/usr/share/ca-certificates/mozilla/Telia_Root_CA_v2.crt",
            "/usr/share/ca-certificates/mozilla/TrustAsia_Global_Root_CA_G3.crt",
            "/usr/share/ca-certificates/mozilla/TrustAsia_Global_Root_CA_G4.crt",
            "/usr/share/ca-certificates/mozilla/Trustwave_Global_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/Trustwave_Global_ECC_P256_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/Trustwave_Global_ECC_P384_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/TunTrust_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/UCA_Extended_Validation_Root.crt",
            "/usr/share/ca-certificates/mozilla/UCA_Global_G2_Root.crt",
            "/usr/share/ca-certificates/mozilla/USERTrust_ECC_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/USERTrust_RSA_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/XRamp_Global_CA_Root.crt",
            "/usr/share/ca-certificates/mozilla/certSIGN_ROOT_CA.crt",
            "/usr/share/ca-certificates/mozilla/certSIGN_Root_CA_G2.crt",
            "/usr/share/ca-certificates/mozilla/e-Szigno_Root_CA_2017.crt",
            "/usr/share/ca-certificates/mozilla/ePKI_Root_Certification_Authority.crt",
            "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_C3.crt",
            "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt",
            "/usr/share/ca-certificates/mozilla/emSign_Root_CA_-_C1.crt",
            "/usr/share/ca-certificates/mozilla/emSign_Root_CA_-_G1.crt",
            "/usr/share/ca-certificates/mozilla/vTrus_ECC_Root_CA.crt",
            "/usr/share/ca-certificates/mozilla/vTrus_Root_CA.crt",
            "/usr/share/doc/ca-certificates/README.Debian",
            "/usr/share/doc/ca-certificates/changelog.gz",
            "/usr/share/doc/ca-certificates/copyright",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/Makefile",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/README",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/ca-certificates-local.triggers",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/changelog",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/compat",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/control",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/copyright",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/postrm",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/rules",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/debian/source/format",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/local/Local_Root_CA.crt",
            "/usr/share/doc/ca-certificates/examples/ca-certificates-local/local/Makefile",
            "/usr/share/man/man8/update-ca-certificates.8.gz"
          ],
          "AnalyzedBy": "dpkg"
        },
        {
          "ID": "media-types@10.0.0",
          "Name": "media-types",
          "Identifier": {
            "PURL": "pkg:deb/debian/media-types@10.0.0?arch=all\u0026distro=debian-12.15",
            "UID": "d381521693a5ea32"
          },
          "Version": "10.0.0",
          "Arch": "all",
          "SrcName": "media-types",
          "SrcVersion": "10.0.0",
          "Licenses": [
            "ad-hoc"
          ],
          "Maintainer": "Mime-Support Packagers \u003cteam+debian-mimesupport-packagers@tracker.debian.org\u003e",
          "Repository": {
            "Class": "official"
          },
          "Layer": {
            "Digest": "sha256:bf7a4185f01524837d19abde915ffde84e64368b250f5b5e9f6f75aea62a11d4",
            "DiffID": "sha256:114dde0fefebbca13165d0da9c500a66190e497a82a53dcaabc3172d630be1e9"
          },
          "InstalledFiles": [
            "/usr/share/bug/media-types/presubj",
            "/usr/share/doc/media-types/changelog.gz",
            "/usr/share/doc/media-types/copyright"
          ],
          "AnalyzedBy": "dpkg"
        },
        {
          "ID": "netbase@6.4",
          "Name": "netbase",
          "Identifier": {
            "PURL": "pkg:deb/debian/netbase@6.4?arch=all\u0026distro=debian-12.15",
            "UID": "64adcbea2e4e887c"
          },
          "Version": "6.4",
          "Arch": "all",
          "SrcName": "netbase",
          "SrcVersion": "6.4",
          "Licenses": [
            "GPL-2.0-only"
          ],
          "Maintainer": "Marco d'Itri \u003cmd@linux.it\u003e",
          "Repository": {
            "Class": "official"
          },
          "Layer": {
            "Digest": "sha256:990a9c434e5e0f11549a8d4a41a1991e621b04e30cd63269adbc97b1dc38fd7e",
            "DiffID": "sha256:8fa10c0194df9b7c054c90dbe482585f768a54428fc90a5b78a0066a123b1bba"
          },
          "InstalledFiles": [
            "/usr/share/doc/netbase/changelog.gz",
            "/usr/share/doc/netbase/copyright"
          ],
          "AnalyzedBy": "dpkg"
        },
        {
          "ID": "tzdata@2026b-0+deb12u1",
          "Name": "tzdata",
          "Identifier": {
            "PURL": "pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all\u0026distro=debian-12.15",
            "UID": "cb2f86311583d698"
          },
          "Version": "2026b",
          "Release": "0+deb12u1",
          "Arch": "all",
          "SrcName": "tzdata",
          "SrcVersion": "2026b",
          "SrcRelease": "0+deb12u1",
          "Licenses": [
            "public-domain"
          ],
          "Maintainer": "GNU Libc Maintainers \u003cdebian-glibc@lists.debian.org\u003e",
          "Repository": {
            "Class": "official"
          },
          "Layer": {
            "Digest": "sha256:39dc083afc39bd8dc43d456fe7ff7d39292e593bb2769972c11bb2e5f9119386",
            "DiffID": "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710"
          },
          "InstalledFiles": [
            "/usr/share/doc/tzdata/README.Debian",
            "/usr/share/doc/tzdata/changelog.Debian.gz",
            "/usr/share/doc/tzdata/changelog.gz",
            "/usr/share/doc/tzdata/copyright",
            "/usr/share/lintian/overrides/tzdata",
            "/usr/share/zoneinfo/Africa/Abidjan",
            "/usr/share/zoneinfo/Africa/Accra",
            "/usr/share/zoneinfo/Africa/Addis_Ababa",
            "/usr/share/zoneinfo/Africa/Algiers",
            "/usr/share/zoneinfo/Africa/Asmara",
            "/usr/share/zoneinfo/Africa/Bamako",
            "/usr/share/zoneinfo/Africa/Bangui",
            "/usr/share/zoneinfo/Africa/Banjul",
            "/usr/share/zoneinfo/Africa/Bissau",
            "/usr/share/zoneinfo/Africa/Blantyre",
            "/usr/share/zoneinfo/Africa/Brazzaville",
            "/usr/share/zoneinfo/Africa/Bujumbura",
            "/usr/share/zoneinfo/Africa/Cairo",
            "/usr/share/zoneinfo/Africa/Casablanca",
            "/usr/share/zoneinfo/Africa/Ceuta",
            "/usr/share/zoneinfo/Africa/Conakry",
            "/usr/share/zoneinfo/Africa/Dakar",
            "/usr/share/zoneinfo/Africa/Dar_es_Salaam",
            "/usr/share/zoneinfo/Africa/Djibouti",
            "/usr/share/zoneinfo/Africa/Douala",
            "/usr/share/zoneinfo/Africa/El_Aaiun",
            "/usr/share/zoneinfo/Africa/Freetown",
            "/usr/share/zoneinfo/Africa/Gaborone",
            "/usr/share/zoneinfo/Africa/Harare",
            "/usr/share/zoneinfo/Africa/Johannesburg",
            "/usr/share/zoneinfo/Africa/Juba",
            "/usr/share/zoneinfo/Africa/Kampala",
            "/usr/share/zoneinfo/Africa/Khartoum",
            "/usr/share/zoneinfo/Africa/Kigali",
            "/usr/share/zoneinfo/Africa/Kinshasa",
            "/usr/share/zoneinfo/Africa/Lagos",
            "/usr/share/zoneinfo/Africa/Libreville",
            "/usr/share/zoneinfo/Africa/Lome",
            "/usr/share/zoneinfo/Africa/Luanda",
            "/usr/share/zoneinfo/Africa/Lubumbashi",
            "/usr/share/zoneinfo/Africa/Lusaka",
            "/usr/share/zoneinfo/Africa/Malabo",
            "/usr/share/zoneinfo/Africa/Maputo",
            "/usr/share/zoneinfo/Africa/Maseru",
            "/usr/share/zoneinfo/Africa/Mbabane",
            "/usr/share/zoneinfo/Africa/Mogadishu",
            "/usr/share/zoneinfo/Africa/Monrovia",
            "/usr/share/zoneinfo/Africa/Nairobi",
            "/usr/share/zoneinfo/Africa/Ndjamena",
            "/usr/share/zoneinfo/Africa/Niamey",
            "/usr/share/zoneinfo/Africa/Nouakchott",
            "/usr/share/zoneinfo/Africa/Ouagadougou",
            "/usr/share/zoneinfo/Africa/Porto-Novo",
            "/usr/share/zoneinfo/Africa/Sao_Tome",
            "/usr/share/zoneinfo/Africa/Tripoli",
            "/usr/share/zoneinfo/Africa/Tunis",
            "/usr/share/zoneinfo/Africa/Windhoek",
            "/usr/share/zoneinfo/America/Adak",
            "/usr/share/zoneinfo/America/Anchorage",
            "/usr/share/zoneinfo/America/Anguilla",
            "/usr/share/zoneinfo/America/Antigua",
            "/usr/share/zoneinfo/America/Araguaina",
            "/usr/share/zoneinfo/America/Argentina/Buenos_Aires",
            "/usr/share/zoneinfo/America/Argentina/Catamarca",
            "/usr/share/zoneinfo/America/Argentina/Cordoba",
            "/usr/share/zoneinfo/America/Argentina/Jujuy",
            "/usr/share/zoneinfo/America/Argentina/La_Rioja",
            "/usr/share/zoneinfo/America/Argentina/Mendoza",
            "/usr/share/zoneinfo/America/Argentina/Rio_Gallegos",
            "/usr/share/zoneinfo/America/Argentina/Salta",
            "/usr/share/zoneinfo/America/Argentina/San_Juan",
            "/usr/share/zoneinfo/America/Argentina/San_Luis",
            "/usr/share/zoneinfo/America/Argentina/Tucuman",
            "/usr/share/zoneinfo/America/Argentina/Ushuaia",
            "/usr/share/zoneinfo/America/Aruba",
            "/usr/share/zoneinfo/America/Asuncion",
            "/usr/share/zoneinfo/America/Atikokan",
            "/usr/share/zoneinfo/America/Bahia",
            "/usr/share/zoneinfo/America/Bahia_Banderas",
            "/usr/share/zoneinfo/America/Barbados",
            "/usr/share/zoneinfo/America/Belem",
            "/usr/share/zoneinfo/America/Belize",
            "/usr/share/zoneinfo/America/Blanc-Sablon",
            "/usr/share/zoneinfo/America/Boa_Vista",
            "/usr/share/zoneinfo/America/Bogota",
            "/usr/share/zoneinfo/America/Boise",
            "/usr/share/zoneinfo/America/Cambridge_Bay",
            "/usr/share/zoneinfo/America/Campo_Grande",
            "/usr/share/zoneinfo/America/Cancun",
            "/usr/share/zoneinfo/America/Caracas",
            "/usr/share/zoneinfo/America/Cayenne",
            "/usr/share/zoneinfo/America/Cayman",
            "/usr/share/zoneinfo/America/Chicago",
            "/usr/share/zoneinfo/America/Chihuahua",
            "/usr/share/zoneinfo/America/Ciudad_Juarez",
            "/usr/share/zoneinfo/America/Costa_Rica",
            "/usr/share/zoneinfo/America/Coyhaique",
            "/usr/share/zoneinfo/America/Creston",
            "/usr/share/zoneinfo/America/Cuiaba",
            "/usr/share/zoneinfo/America/Curacao",
            "/usr/share/zoneinfo/America/Danmarkshavn",
            "/usr/share/zoneinfo/America/Dawson",
            "/usr/share/zoneinfo/America/Dawson_Creek",
            "/usr/share/zoneinfo/America/Denver",
            "/usr/share/zoneinfo/America/Detroit",
            "/usr/share/zoneinfo/America/Dominica",
            "/usr/share/zoneinfo/America/Edmonton",
            "/usr/share/zoneinfo/America/Eirunepe",
            "/usr/share/zoneinfo/America/El_Salvador",
            "/usr/share/zoneinfo/America/Fort_Nelson",
            "/usr/share/zoneinfo/America/Fortaleza",
            "/usr/share/zoneinfo/America/Glace_Bay",
            "/usr/share/zoneinfo/America/Goose_Bay",
            "/usr/share/zoneinfo/America/Grand_Turk",
            "/usr/share/zoneinfo/America/Grenada",
            "/usr/share/zoneinfo/America/Guadeloupe",
            "/usr/share/zoneinfo/America/Guatemala",
            "/usr/share/zoneinfo/America/Guayaquil",
            "/usr/share/zoneinfo/America/Guyana",
            "/usr/share/zoneinfo/America/Halifax",
            "/usr/share/zoneinfo/America/Havana",
            "/usr/share/zoneinfo/America/Hermosillo",
            "/usr/share/zoneinfo/America/Indiana/Indianapolis",
            "/usr/share/zoneinfo/America/Indiana/Knox",
            "/usr/share/zoneinfo/America/Indiana/Marengo",
            "/usr/share/zoneinfo/America/Indiana/Petersburg",
            "/usr/share/zoneinfo/America/Indiana/Tell_City",
            "/usr/share/zoneinfo/America/Indiana/Vevay",
            "/usr/share/zoneinfo/America/Indiana/Vincennes",
            "/usr/share/zoneinfo/America/Indiana/Winamac",
            "/usr/share/zoneinfo/America/Inuvik",
            "/usr/share/zoneinfo/America/Iqaluit",
            "/usr/share/zoneinfo/America/Jamaica",
            "/usr/share/zoneinfo/America/Juneau",
            "/usr/share/zoneinfo/America/Kentucky/Louisville",
            "/usr/share/zoneinfo/America/Kentucky/Monticello",
            "/usr/share/zoneinfo/America/La_Paz",
            "/usr/share/zoneinfo/America/Lima",
            "/usr/share/zoneinfo/America/Los_Angeles",
            "/usr/share/zoneinfo/America/Maceio",
            "/usr/share/zoneinfo/America/Managua",
            "/usr/share/zoneinfo/America/Manaus",
            "/usr/share/zoneinfo/America/Martinique",
            "/usr/share/zoneinfo/America/Matamoros",
            "/usr/share/zoneinfo/America/Mazatlan",
            "/usr/share/zoneinfo/America/Menominee",
            "/usr/share/zoneinfo/America/Merida",
            "/usr/share/zoneinfo/America/Metlakatla",
            "/usr/share/zoneinfo/America/Mexico_City",
            "/usr/share/zoneinfo/America/Miquelon",
            "/usr/share/zoneinfo/America/Moncton",
            "/usr/share/zoneinfo/America/Monterrey",
            "/usr/share/zoneinfo/America/Montevideo",
            "/usr/share/zoneinfo/America/Montserrat",
            "/usr/share/zoneinfo/America/Nassau",
            "/usr/share/zoneinfo/America/New_York",
            "/usr/share/zoneinfo/America/Nome",
            "/usr/share/zoneinfo/America/Noronha",
            "/usr/share/zoneinfo/America/North_Dakota/Beulah",
            "/usr/share/zoneinfo/America/North_Dakota/Center",
            "/usr/share/zoneinfo/America/North_Dakota/New_Salem",
            "/usr/share/zoneinfo/America/Nuuk",
            "/usr/share/zoneinfo/America/Ojinaga",
            "/usr/share/zoneinfo/America/Panama",
            "/usr/share/zoneinfo/America/Paramaribo",
            "/usr/share/zoneinfo/America/Phoenix",
            "/usr/share/zoneinfo/America/Port-au-Prince",
            "/usr/share/zoneinfo/America/Port_of_Spain",
            "/usr/share/zoneinfo/America/Porto_Velho",
            "/usr/share/zoneinfo/America/Puerto_Rico",
            "/usr/share/zoneinfo/America/Punta_Arenas",
            "/usr/share/zoneinfo/America/Rankin_Inlet",
            "/usr/share/zoneinfo/America/Recife",
            "/usr/share/zoneinfo/America/Regina",
            "/usr/share/zoneinfo/America/Resolute",
            "/usr/share/zoneinfo/America/Rio_Branco",
            "/usr/share/zoneinfo/America/Santarem",
            "/usr/share/zoneinfo/America/Santiago",
            "/usr/share/zoneinfo/America/Santo_Domingo",
            "/usr/share/zoneinfo/America/Sao_Paulo",
            "/usr/share/zoneinfo/America/Scoresbysund",
            "/usr/share/zoneinfo/America/Sitka",
            "/usr/share/zoneinfo/America/St_Johns",
            "/usr/share/zoneinfo/America/St_Kitts",
            "/usr/share/zoneinfo/America/St_Lucia",
            "/usr/share/zoneinfo/America/St_Thomas",
            "/usr/share/zoneinfo/America/St_Vincent",
            "/usr/share/zoneinfo/America/Swift_Current",
            "/usr/share/zoneinfo/America/Tegucigalpa",
            "/usr/share/zoneinfo/America/Thule",
            "/usr/share/zoneinfo/America/Tijuana",
            "/usr/share/zoneinfo/America/Toronto",
            "/usr/share/zoneinfo/America/Tortola",
            "/usr/share/zoneinfo/America/Vancouver",
            "/usr/share/zoneinfo/America/Whitehorse",
            "/usr/share/zoneinfo/America/Winnipeg",
            "/usr/share/zoneinfo/America/Yakutat",
            "/usr/share/zoneinfo/Antarctica/Casey",
            "/usr/share/zoneinfo/Antarctica/Davis",
            "/usr/share/zoneinfo/Antarctica/DumontDUrville",
            "/usr/share/zoneinfo/Antarctica/Macquarie",
            "/usr/share/zoneinfo/Antarctica/Mawson",
            "/usr/share/zoneinfo/Antarctica/McMurdo",
            "/usr/share/zoneinfo/Antarctica/Palmer",
            "/usr/share/zoneinfo/Antarctica/Rothera",
            "/usr/share/zoneinfo/Antarctica/Syowa",
            "/usr/share/zoneinfo/Antarctica/Troll",
            "/usr/share/zoneinfo/Antarctica/Vostok",
            "/usr/share/zoneinfo/Asia/Aden",
            "/usr/share/zoneinfo/Asia/Almaty",
            "/usr/share/zoneinfo/Asia/Amman",
            "/usr/share/zoneinfo/Asia/Anadyr",
            "/usr/share/zoneinfo/Asia/Aqtau",
            "/usr/share/zoneinfo/Asia/Aqtobe",
            "/usr/share/zoneinfo/Asia/Ashgabat",
            "/usr/share/zoneinfo/Asia/Atyrau",
            "/usr/share/zoneinfo/Asia/Baghdad",
            "/usr/share/zoneinfo/Asia/Bahrain",
            "/usr/share/zoneinfo/Asia/Baku",
            "/usr/share/zoneinfo/Asia/Bangkok",
            "/usr/share/zoneinfo/Asia/Barnaul",
            "/usr/share/zoneinfo/Asia/Beirut",
            "/usr/share/zoneinfo/Asia/Bishkek",
            "/usr/share/zoneinfo/Asia/Brunei",
            "/usr/share/zoneinfo/Asia/Chita",
            "/usr/share/zoneinfo/Asia/Colombo",
            "/usr/share/zoneinfo/Asia/Damascus",
            "/usr/share/zoneinfo/Asia/Dhaka",
            "/usr/share/zoneinfo/Asia/Dili",
            "/usr/share/zoneinfo/Asia/Dubai",
            "/usr/share/zoneinfo/Asia/Dushanbe",
            "/usr/share/zoneinfo/Asia/Famagusta",
            "/usr/share/zoneinfo/Asia/Gaza",
            "/usr/share/zoneinfo/Asia/Hebron",
            "/usr/share/zoneinfo/Asia/Ho_Chi_Minh",
            "/usr/share/zoneinfo/Asia/Hong_Kong",
            "/usr/share/zoneinfo/Asia/Hovd",
            "/usr/share/zoneinfo/Asia/Irkutsk",
            "/usr/share/zoneinfo/Asia/Jakarta",
            "/usr/share/zoneinfo/Asia/Jayapura",
            "/usr/share/zoneinfo/Asia/Jerusalem",
            "/usr/share/zoneinfo/Asia/Kabul",
            "/usr/share/zoneinfo/Asia/Kamchatka",
            "/usr/share/zoneinfo/Asia/Karachi",
            "/usr/share/zoneinfo/Asia/Kathmandu",
            "/usr/share/zoneinfo/Asia/Khandyga",
            "/usr/share/zoneinfo/Asia/Kolkata",
            "/usr/share/zoneinfo/Asia/Krasnoyarsk",
            "/usr/share/zoneinfo/Asia/Kuala_Lumpur",
            "/usr/share/zoneinfo/Asia/Kuching",
            "/usr/share/zoneinfo/Asia/Kuwait",
            "/usr/share/zoneinfo/Asia/Macau",
            "/usr/share/zoneinfo/Asia/Magadan",
            "/usr/share/zoneinfo/Asia/Makassar",
            "/usr/share/zoneinfo/Asia/Manila",
            "/usr/share/zoneinfo/Asia/Muscat",
            "/usr/share/zoneinfo/Asia/Nicosia",
            "/usr/share/zoneinfo/Asia/Novokuznetsk",
            "/usr/share/zoneinfo/Asia/Novosibirsk",
            "/usr/share/zoneinfo/Asia/Omsk",
            "/usr/share/zoneinfo/Asia/Oral",
            "/usr/share/zoneinfo/Asia/Phnom_Penh",
            "/usr/share/zoneinfo/Asia/Pontianak",
            "/usr/share/zoneinfo/Asia/Pyongyang",
            "/usr/share/zoneinfo/Asia/Qatar",
            "/usr/share/zoneinfo/Asia/Qostanay",
            "/usr/share/zoneinfo/Asia/Qyzylorda",
            "/usr/share/zoneinfo/Asia/Riyadh",
            "/usr/share/zoneinfo/Asia/Sakhalin",
            "/usr/share/zoneinfo/Asia/Samarkand",
            "/usr/share/zoneinfo/Asia/Seoul",
            "/usr/share/zoneinfo/Asia/Shanghai",
            "/usr/share/zoneinfo/Asia/Singapore",
            "/usr/share/zoneinfo/Asia/Srednekolymsk",
            "/usr/share/zoneinfo/Asia/Taipei",
            "/usr/share/zoneinfo/Asia/Tashkent",
            "/usr/share/zoneinfo/Asia/Tbilisi",
            "/usr/share/zoneinfo/Asia/Tehran",
            "/usr/share/zoneinfo/Asia/Thimphu",
            "/usr/share/zoneinfo/Asia/Tokyo",
            "/usr/share/zoneinfo/Asia/Tomsk",
            "/usr/share/zoneinfo/Asia/Ulaanbaatar",
            "/usr/share/zoneinfo/Asia/Urumqi",
            "/usr/share/zoneinfo/Asia/Ust-Nera",
            "/usr/share/zoneinfo/Asia/Vientiane",
            "/usr/share/zoneinfo/Asia/Vladivostok",
            "/usr/share/zoneinfo/Asia/Yakutsk",
            "/usr/share/zoneinfo/Asia/Yangon",
            "/usr/share/zoneinfo/Asia/Yekaterinburg",
            "/usr/share/zoneinfo/Asia/Yerevan",
            "/usr/share/zoneinfo/Atlantic/Azores",
            "/usr/share/zoneinfo/Atlantic/Bermuda",
            "/usr/share/zoneinfo/Atlantic/Canary",
            "/usr/share/zoneinfo/Atlantic/Cape_Verde",
            "/usr/share/zoneinfo/Atlantic/Faroe",
            "/usr/share/zoneinfo/Atlantic/Madeira",
            "/usr/share/zoneinfo/Atlantic/Reykjavik",
            "/usr/share/zoneinfo/Atlantic/South_Georgia",
            "/usr/share/zoneinfo/Atlantic/St_Helena",
            "/usr/share/zoneinfo/Atlantic/Stanley",
            "/usr/share/zoneinfo/Australia/Adelaide",
            "/usr/share/zoneinfo/Australia/Brisbane",
            "/usr/share/zoneinfo/Australia/Broken_Hill",
            "/usr/share/zoneinfo/Australia/Darwin",
            "/usr/share/zoneinfo/Australia/Eucla",
            "/usr/share/zoneinfo/Australia/Hobart",
            "/usr/share/zoneinfo/Australia/Lindeman",
            "/usr/share/zoneinfo/Australia/Lord_Howe",
            "/usr/share/zoneinfo/Australia/Melbourne",
            "/usr/share/zoneinfo/Australia/Perth",
            "/usr/share/zoneinfo/Australia/Sydney",
            "/usr/share/zoneinfo/CET",
            "/usr/share/zoneinfo/CST6CDT",
            "/usr/share/zoneinfo/EET",
            "/usr/share/zoneinfo/EST",
            "/usr/share/zoneinfo/EST5EDT",
            "/usr/share/zoneinfo/Etc/GMT",
            "/usr/share/zoneinfo/Etc/GMT+1",
            "/usr/share/zoneinfo/Etc/GMT+10",
            "/usr/share/zoneinfo/Etc/GMT+11",
            "/usr/share/zoneinfo/Etc/GMT+12",
            "/usr/share/zoneinfo/Etc/GMT+2",
            "/usr/share/zoneinfo/Etc/GMT+3",
            "/usr/share/zoneinfo/Etc/GMT+4",
            "/usr/share/zoneinfo/Etc/GMT+5",
            "/usr/share/zoneinfo/Etc/GMT+6",
            "/usr/share/zoneinfo/Etc/GMT+7",
            "/usr/share/zoneinfo/Etc/GMT+8",
            "/usr/share/zoneinfo/Etc/GMT+9",
            "/usr/share/zoneinfo/Etc/GMT-1",
            "/usr/share/zoneinfo/Etc/GMT-10",
            "/usr/share/zoneinfo/Etc/GMT-11",
            "/usr/share/zoneinfo/Etc/GMT-12",
            "/usr/share/zoneinfo/Etc/GMT-13",
            "/usr/share/zoneinfo/Etc/GMT-14",
            "/usr/share/zoneinfo/Etc/GMT-2",
            "/usr/share/zoneinfo/Etc/GMT-3",
            "/usr/share/zoneinfo/Etc/GMT-4",
            "/usr/share/zoneinfo/Etc/GMT-5",
            "/usr/share/zoneinfo/Etc/GMT-6",
            "/usr/share/zoneinfo/Etc/GMT-7",
            "/usr/share/zoneinfo/Etc/GMT-8",
            "/usr/share/zoneinfo/Etc/GMT-9",
            "/usr/share/zoneinfo/Etc/UTC",
            "/usr/share/zoneinfo/Europe/Amsterdam",
            "/usr/share/zoneinfo/Europe/Andorra",
            "/usr/share/zoneinfo/Europe/Astrakhan",
            "/usr/share/zoneinfo/Europe/Athens",
            "/usr/share/zoneinfo/Europe/Belgrade",
            "/usr/share/zoneinfo/Europe/Berlin",
            "/usr/share/zoneinfo/Europe/Brussels",
            "/usr/share/zoneinfo/Europe/Bucharest",
            "/usr/share/zoneinfo/Europe/Budapest",
            "/usr/share/zoneinfo/Europe/Chisinau",
            "/usr/share/zoneinfo/Europe/Copenhagen",
            "/usr/share/zoneinfo/Europe/Dublin",
            "/usr/share/zoneinfo/Europe/Gibraltar",
            "/usr/share/zoneinfo/Europe/Guernsey",
            "/usr/share/zoneinfo/Europe/Helsinki",
            "/usr/share/zoneinfo/Europe/Isle_of_Man",
            "/usr/share/zoneinfo/Europe/Istanbul",
            "/usr/share/zoneinfo/Europe/Jersey",
            "/usr/share/zoneinfo/Europe/Kaliningrad",
            "/usr/share/zoneinfo/Europe/Kirov",
            "/usr/share/zoneinfo/Europe/Kyiv",
            "/usr/share/zoneinfo/Europe/Lisbon",
            "/usr/share/zoneinfo/Europe/Ljubljana",
            "/usr/share/zoneinfo/Europe/London",
            "/usr/share/zoneinfo/Europe/Luxembourg",
            "/usr/share/zoneinfo/Europe/Madrid",
            "/usr/share/zoneinfo/Europe/Malta",
            "/usr/share/zoneinfo/Europe/Minsk",
            "/usr/share/zoneinfo/Europe/Monaco",
            "/usr/share/zoneinfo/Europe/Moscow",
            "/usr/share/zoneinfo/Europe/Oslo",
            "/usr/share/zoneinfo/Europe/Paris",
            "/usr/share/zoneinfo/Europe/Prague",
            "/usr/share/zoneinfo/Europe/Riga",
            "/usr/share/zoneinfo/Europe/Rome",
            "/usr/share/zoneinfo/Europe/Samara",
            "/usr/share/zoneinfo/Europe/Sarajevo",
            "/usr/share/zoneinfo/Europe/Saratov",
            "/usr/share/zoneinfo/Europe/Simferopol",
            "/usr/share/zoneinfo/Europe/Skopje",
            "/usr/share/zoneinfo/Europe/Sofia",
            "/usr/share/zoneinfo/Europe/Stockholm",
            "/usr/share/zoneinfo/Europe/Tallinn",
            "/usr/share/zoneinfo/Europe/Tirane",
            "/usr/share/zoneinfo/Europe/Ulyanovsk",
            "/usr/share/zoneinfo/Europe/Vaduz",
            "/usr/share/zoneinfo/Europe/Vienna",
            "/usr/share/zoneinfo/Europe/Vilnius",
            "/usr/share/zoneinfo/Europe/Volgograd",
            "/usr/share/zoneinfo/Europe/Warsaw",
            "/usr/share/zoneinfo/Europe/Zagreb",
            "/usr/share/zoneinfo/Europe/Zurich",
            "/usr/share/zoneinfo/Factory",
            "/usr/share/zoneinfo/HST",
            "/usr/share/zoneinfo/Indian/Antananarivo",
            "/usr/share/zoneinfo/Indian/Chagos",
            "/usr/share/zoneinfo/Indian/Christmas",
            "/usr/share/zoneinfo/Indian/Cocos",
            "/usr/share/zoneinfo/Indian/Comoro",
            "/usr/share/zoneinfo/Indian/Kerguelen",
            "/usr/share/zoneinfo/Indian/Mahe",
            "/usr/share/zoneinfo/Indian/Maldives",
            "/usr/share/zoneinfo/Indian/Mauritius",
            "/usr/share/zoneinfo/Indian/Mayotte",
            "/usr/share/zoneinfo/Indian/Reunion",
            "/usr/share/zoneinfo/MET",
            "/usr/share/zoneinfo/MST",
            "/usr/share/zoneinfo/MST7MDT",
            "/usr/share/zoneinfo/PST8PDT",
            "/usr/share/zoneinfo/Pacific/Apia",
            "/usr/share/zoneinfo/Pacific/Auckland",
            "/usr/share/zoneinfo/Pacific/Bougainville",
            "/usr/share/zoneinfo/Pacific/Chatham",
            "/usr/share/zoneinfo/Pacific/Chuuk",
            "/usr/share/zoneinfo/Pacific/Easter",
            "/usr/share/zoneinfo/Pacific/Efate",
            "/usr/share/zoneinfo/Pacific/Fakaofo",
            "/usr/share/zoneinfo/Pacific/Fiji",
            "/usr/share/zoneinfo/Pacific/Funafuti",
            "/usr/share/zoneinfo/Pacific/Galapagos",
            "/usr/share/zoneinfo/Pacific/Gambier",
            "/usr/share/zoneinfo/Pacific/Guadalcanal",
            "/usr/share/zoneinfo/Pacific/Guam",
            "/usr/share/zoneinfo/Pacific/Honolulu",
            "/usr/share/zoneinfo/Pacific/Kanton",
            "/usr/share/zoneinfo/Pacific/Kiritimati",
            "/usr/share/zoneinfo/Pacific/Kosrae",
            "/usr/share/zoneinfo/Pacific/Kwajalein",
            "/usr/share/zoneinfo/Pacific/Majuro",
            "/usr/share/zoneinfo/Pacific/Marquesas",
            "/usr/share/zoneinfo/Pacific/Midway",
            "/usr/share/zoneinfo/Pacific/Nauru",
            "/usr/share/zoneinfo/Pacific/Niue",
            "/usr/share/zoneinfo/Pacific/Norfolk",
            "/usr/share/zoneinfo/Pacific/Noumea",
            "/usr/share/zoneinfo/Pacific/Pago_Pago",
            "/usr/share/zoneinfo/Pacific/Palau",
            "/usr/share/zoneinfo/Pacific/Pitcairn",
            "/usr/share/zoneinfo/Pacific/Pohnpei",
            "/usr/share/zoneinfo/Pacific/Port_Moresby",
            "/usr/share/zoneinfo/Pacific/Rarotonga",
            "/usr/share/zoneinfo/Pacific/Saipan",
            "/usr/share/zoneinfo/Pacific/Tahiti",
            "/usr/share/zoneinfo/Pacific/Tarawa",
            "/usr/share/zoneinfo/Pacific/Tongatapu",
            "/usr/share/zoneinfo/Pacific/Wake",
            "/usr/share/zoneinfo/Pacific/Wallis",
            "/usr/share/zoneinfo/WET",
            "/usr/share/zoneinfo/iso3166.tab",
            "/usr/share/zoneinfo/leap-seconds.list",
            "/usr/share/zoneinfo/leapseconds",
            "/usr/share/zoneinfo/right/Africa/Abidjan",
            "/usr/share/zoneinfo/right/Africa/Accra",
            "/usr/share/zoneinfo/right/Africa/Addis_Ababa",
            "/usr/share/zoneinfo/right/Africa/Algiers",
            "/usr/share/zoneinfo/right/Africa/Asmara",
            "/usr/share/zoneinfo/right/Africa/Bamako",
            "/usr/share/zoneinfo/right/Africa/Bangui",
            "/usr/share/zoneinfo/right/Africa/Banjul",
            "/usr/share/zoneinfo/right/Africa/Bissau",
            "/usr/share/zoneinfo/right/Africa/Blantyre",
            "/usr/share/zoneinfo/right/Africa/Brazzaville",
            "/usr/share/zoneinfo/right/Africa/Bujumbura",
            "/usr/share/zoneinfo/right/Africa/Cairo",
            "/usr/share/zoneinfo/right/Africa/Casablanca",
            "/usr/share/zoneinfo/right/Africa/Ceuta",
            "/usr/share/zoneinfo/right/Africa/Conakry",
            "/usr/share/zoneinfo/right/Africa/Dakar",
            "/usr/share/zoneinfo/right/Africa/Dar_es_Salaam",
            "/usr/share/zoneinfo/right/Africa/Djibouti",
            "/usr/share/zoneinfo/right/Africa/Douala",
            "/usr/share/zoneinfo/right/Africa/El_Aaiun",
            "/usr/share/zoneinfo/right/Africa/Freetown",
            "/usr/share/zoneinfo/right/Africa/Gaborone",
            "/usr/share/zoneinfo/right/Africa/Harare",
            "/usr/share/zoneinfo/right/Africa/Johannesburg",
            "/usr/share/zoneinfo/right/Africa/Juba",
            "/usr/share/zoneinfo/right/Africa/Kampala",
            "/usr/share/zoneinfo/right/Africa/Khartoum",
            "/usr/share/zoneinfo/right/Africa/Kigali",
            "/usr/share/zoneinfo/right/Africa/Kinshasa",
            "/usr/share/zoneinfo/right/Africa/Lagos",
            "/usr/share/zoneinfo/right/Africa/Libreville",
            "/usr/share/zoneinfo/right/Africa/Lome",
            "/usr/share/zoneinfo/right/Africa/Luanda",
            "/usr/share/zoneinfo/right/Africa/Lubumbashi",
            "/usr/share/zoneinfo/right/Africa/Lusaka",
            "/usr/share/zoneinfo/right/Africa/Malabo",
            "/usr/share/zoneinfo/right/Africa/Maputo",
            "/usr/share/zoneinfo/right/Africa/Maseru",
            "/usr/share/zoneinfo/right/Africa/Mbabane",
            "/usr/share/zoneinfo/right/Africa/Mogadishu",
            "/usr/share/zoneinfo/right/Africa/Monrovia",
            "/usr/share/zoneinfo/right/Africa/Nairobi",
            "/usr/share/zoneinfo/right/Africa/Ndjamena",
            "/usr/share/zoneinfo/right/Africa/Niamey",
            "/usr/share/zoneinfo/right/Africa/Nouakchott",
            "/usr/share/zoneinfo/right/Africa/Ouagadougou",
            "/usr/share/zoneinfo/right/Africa/Porto-Novo",
            "/usr/share/zoneinfo/right/Africa/Sao_Tome",
            "/usr/share/zoneinfo/right/Africa/Tripoli",
            "/usr/share/zoneinfo/right/Africa/Tunis",
            "/usr/share/zoneinfo/right/Africa/Windhoek",
            "/usr/share/zoneinfo/right/America/Adak",
            "/usr/share/zoneinfo/right/America/Anchorage",
            "/usr/share/zoneinfo/right/America/Anguilla",
            "/usr/share/zoneinfo/right/America/Antigua",
            "/usr/share/zoneinfo/right/America/Araguaina",
            "/usr/share/zoneinfo/right/America/Argentina/Buenos_Aires",
            "/usr/share/zoneinfo/right/America/Argentina/Catamarca",
            "/usr/share/zoneinfo/right/America/Argentina/Cordoba",
            "/usr/share/zoneinfo/right/America/Argentina/Jujuy",
            "/usr/share/zoneinfo/right/America/Argentina/La_Rioja",
            "/usr/share/zoneinfo/right/America/Argentina/Mendoza",
            "/usr/share/zoneinfo/right/America/Argentina/Rio_Gallegos",
            "/usr/share/zoneinfo/right/America/Argentina/Salta",
            "/usr/share/zoneinfo/right/America/Argentina/San_Juan",
            "/usr/share/zoneinfo/right/America/Argentina/San_Luis",
            "/usr/share/zoneinfo/right/America/Argentina/Tucuman",
            "/usr/share/zoneinfo/right/America/Argentina/Ushuaia",
            "/usr/share/zoneinfo/right/America/Aruba",
            "/usr/share/zoneinfo/right/America/Asuncion",
            "/usr/share/zoneinfo/right/America/Atikokan",
            "/usr/share/zoneinfo/right/America/Bahia",
            "/usr/share/zoneinfo/right/America/Bahia_Banderas",
            "/usr/share/zoneinfo/right/America/Barbados",
            "/usr/share/zoneinfo/right/America/Belem",
            "/usr/share/zoneinfo/right/America/Belize",
            "/usr/share/zoneinfo/right/America/Blanc-Sablon",
            "/usr/share/zoneinfo/right/America/Boa_Vista",
            "/usr/share/zoneinfo/right/America/Bogota",
            "/usr/share/zoneinfo/right/America/Boise",
            "/usr/share/zoneinfo/right/America/Cambridge_Bay",
            "/usr/share/zoneinfo/right/America/Campo_Grande",
            "/usr/share/zoneinfo/right/America/Cancun",
            "/usr/share/zoneinfo/right/America/Caracas",
            "/usr/share/zoneinfo/right/America/Cayenne",
            "/usr/share/zoneinfo/right/America/Cayman",
            "/usr/share/zoneinfo/right/America/Chicago",
            "/usr/share/zoneinfo/right/America/Chihuahua",
            "/usr/share/zoneinfo/right/America/Ciudad_Juarez",
            "/usr/share/zoneinfo/right/America/Costa_Rica",
            "/usr/share/zoneinfo/right/America/Coyhaique",
            "/usr/share/zoneinfo/right/America/Creston",
            "/usr/share/zoneinfo/right/America/Cuiaba",
            "/usr/share/zoneinfo/right/America/Curacao",
            "/usr/share/zoneinfo/right/America/Danmarkshavn",
            "/usr/share/zoneinfo/right/America/Dawson",
            "/usr/share/zoneinfo/right/America/Dawson_Creek",
            "/usr/share/zoneinfo/right/America/Denver",
            "/usr/share/zoneinfo/right/America/Detroit",
            "/usr/share/zoneinfo/right/America/Dominica",
            "/usr/share/zoneinfo/right/America/Edmonton",
            "/usr/share/zoneinfo/right/America/Eirunepe",
            "/usr/share/zoneinfo/right/America/El_Salvador",
            "/usr/share/zoneinfo/right/America/Fort_Nelson",
            "/usr/share/zoneinfo/right/America/Fortaleza",
            "/usr/share/zoneinfo/right/America/Glace_Bay",
            "/usr/share/zoneinfo/right/America/Goose_Bay",
            "/usr/share/zoneinfo/right/America/Grand_Turk",
            "/usr/share/zoneinfo/right/America/Grenada",
            "/usr/share/zoneinfo/right/America/Guadeloupe",
            "/usr/share/zoneinfo/right/America/Guatemala",
            "/usr/share/zoneinfo/right/America/Guayaquil",
            "/usr/share/zoneinfo/right/America/Guyana",
            "/usr/share/zoneinfo/right/America/Halifax",
            "/usr/share/zoneinfo/right/America/Havana",
            "/usr/share/zoneinfo/right/America/Hermosillo",
            "/usr/share/zoneinfo/right/America/Indiana/Indianapolis",
            "/usr/share/zoneinfo/right/America/Indiana/Knox",
            "/usr/share/zoneinfo/right/America/Indiana/Marengo",
            "/usr/share/zoneinfo/right/America/Indiana/Petersburg",
            "/usr/share/zoneinfo/right/America/Indiana/Tell_City",
            "/usr/share/zoneinfo/right/America/Indiana/Vevay",
            "/usr/share/zoneinfo/right/America/Indiana/Vincennes",
            "/usr/share/zoneinfo/right/America/Indiana/Winamac",
            "/usr/share/zoneinfo/right/America/Inuvik",
            "/usr/share/zoneinfo/right/America/Iqaluit",
            "/usr/share/zoneinfo/right/America/Jamaica",
            "/usr/share/zoneinfo/right/America/Juneau",
            "/usr/share/zoneinfo/right/America/Kentucky/Louisville",
            "/usr/share/zoneinfo/right/America/Kentucky/Monticello",
            "/usr/share/zoneinfo/right/America/La_Paz",
            "/usr/share/zoneinfo/right/America/Lima",
            "/usr/share/zoneinfo/right/America/Los_Angeles",
            "/usr/share/zoneinfo/right/America/Maceio",
            "/usr/share/zoneinfo/right/America/Managua",
            "/usr/share/zoneinfo/right/America/Manaus",
            "/usr/share/zoneinfo/right/America/Martinique",
            "/usr/share/zoneinfo/right/America/Matamoros",
            "/usr/share/zoneinfo/right/America/Mazatlan",
            "/usr/share/zoneinfo/right/America/Menominee",
            "/usr/share/zoneinfo/right/America/Merida",
            "/usr/share/zoneinfo/right/America/Metlakatla",
            "/usr/share/zoneinfo/right/America/Mexico_City",
            "/usr/share/zoneinfo/right/America/Miquelon",
            "/usr/share/zoneinfo/right/America/Moncton",
            "/usr/share/zoneinfo/right/America/Monterrey",
            "/usr/share/zoneinfo/right/America/Montevideo",
            "/usr/share/zoneinfo/right/America/Montserrat",
            "/usr/share/zoneinfo/right/America/Nassau",
            "/usr/share/zoneinfo/right/America/New_York",
            "/usr/share/zoneinfo/right/America/Nome",
            "/usr/share/zoneinfo/right/America/Noronha",
            "/usr/share/zoneinfo/right/America/North_Dakota/Beulah",
            "/usr/share/zoneinfo/right/America/North_Dakota/Center",
            "/usr/share/zoneinfo/right/America/North_Dakota/New_Salem",
            "/usr/share/zoneinfo/right/America/Nuuk",
            "/usr/share/zoneinfo/right/America/Ojinaga",
            "/usr/share/zoneinfo/right/America/Panama",
            "/usr/share/zoneinfo/right/America/Paramaribo",
            "/usr/share/zoneinfo/right/America/Phoenix",
            "/usr/share/zoneinfo/right/America/Port-au-Prince",
            "/usr/share/zoneinfo/right/America/Port_of_Spain",
            "/usr/share/zoneinfo/right/America/Porto_Velho",
            "/usr/share/zoneinfo/right/America/Puerto_Rico",
            "/usr/share/zoneinfo/right/America/Punta_Arenas",
            "/usr/share/zoneinfo/right/America/Rankin_Inlet",
            "/usr/share/zoneinfo/right/America/Recife",
            "/usr/share/zoneinfo/right/America/Regina",
            "/usr/share/zoneinfo/right/America/Resolute",
            "/usr/share/zoneinfo/right/America/Rio_Branco",
            "/usr/share/zoneinfo/right/America/Santarem",
            "/usr/share/zoneinfo/right/America/Santiago",
            "/usr/share/zoneinfo/right/America/Santo_Domingo",
            "/usr/share/zoneinfo/right/America/Sao_Paulo",
            "/usr/share/zoneinfo/right/America/Scoresbysund",
            "/usr/share/zoneinfo/right/America/Sitka",
            "/usr/share/zoneinfo/right/America/St_Johns",
            "/usr/share/zoneinfo/right/America/St_Kitts",
            "/usr/share/zoneinfo/right/America/St_Lucia",
            "/usr/share/zoneinfo/right/America/St_Thomas",
            "/usr/share/zoneinfo/right/America/St_Vincent",
            "/usr/share/zoneinfo/right/America/Swift_Current",
            "/usr/share/zoneinfo/right/America/Tegucigalpa",
            "/usr/share/zoneinfo/right/America/Thule",
            "/usr/share/zoneinfo/right/America/Tijuana",
            "/usr/share/zoneinfo/right/America/Toronto",
            "/usr/share/zoneinfo/right/America/Tortola",
            "/usr/share/zoneinfo/right/America/Vancouver",
            "/usr/share/zoneinfo/right/America/Whitehorse",
            "/usr/share/zoneinfo/right/America/Winnipeg",
            "/usr/share/zoneinfo/right/America/Yakutat",
            "/usr/share/zoneinfo/right/Antarctica/Casey",
            "/usr/share/zoneinfo/right/Antarctica/Davis",
            "/usr/share/zoneinfo/right/Antarctica/DumontDUrville",
            "/usr/share/zoneinfo/right/Antarctica/Macquarie",
            "/usr/share/zoneinfo/right/Antarctica/Mawson",
            "/usr/share/zoneinfo/right/Antarctica/McMurdo",
            "/usr/share/zoneinfo/right/Antarctica/Palmer",
            "/usr/share/zoneinfo/right/Antarctica/Rothera",
            "/usr/share/zoneinfo/right/Antarctica/Syowa",
            "/usr/share/zoneinfo/right/Antarctica/Troll",
            "/usr/share/zoneinfo/right/Antarctica/Vostok",
            "/usr/share/zoneinfo/right/Asia/Aden",
            "/usr/share/zoneinfo/right/Asia/Almaty",
            "/usr/share/zoneinfo/right/Asia/Amman",
            "/usr/share/zoneinfo/right/Asia/Anadyr",
            "/usr/share/zoneinfo/right/Asia/Aqtau",
            "/usr/share/zoneinfo/right/Asia/Aqtobe",
            "/usr/share/zoneinfo/right/Asia/Ashgabat",
            "/usr/share/zoneinfo/right/Asia/Atyrau",
            "/usr/share/zoneinfo/right/Asia/Baghdad",
            "/usr/share/zoneinfo/right/Asia/Bahrain",
            "/usr/share/zoneinfo/right/Asia/Baku",
            "/usr/share/zoneinfo/right/Asia/Bangkok",
            "/usr/share/zoneinfo/right/Asia/Barnaul",
            "/usr/share/zoneinfo/right/Asia/Beirut",
            "/usr/share/zoneinfo/right/Asia/Bishkek",
            "/usr/share/zoneinfo/right/Asia/Brunei",
            "/usr/share/zoneinfo/right/Asia/Chita",
            "/usr/share/zoneinfo/right/Asia/Colombo",
            "/usr/share/zoneinfo/right/Asia/Damascus",
            "/usr/share/zoneinfo/right/Asia/Dhaka",
            "/usr/share/zoneinfo/right/Asia/Dili",
            "/usr/share/zoneinfo/right/Asia/Dubai",
            "/usr/share/zoneinfo/right/Asia/Dushanbe",
            "/usr/share/zoneinfo/right/Asia/Famagusta",
            "/usr/share/zoneinfo/right/Asia/Gaza",
            "/usr/share/zoneinfo/right/Asia/Hebron",
            "/usr/share/zoneinfo/right/Asia/Ho_Chi_Minh",
            "/usr/share/zoneinfo/right/Asia/Hong_Kong",
            "/usr/share/zoneinfo/right/Asia/Hovd",
            "/usr/share/zoneinfo/right/Asia/Irkutsk",
            "/usr/share/zoneinfo/right/Asia/Jakarta",
            "/usr/share/zoneinfo/right/Asia/Jayapura",
            "/usr/share/zoneinfo/right/Asia/Jerusalem",
            "/usr/share/zoneinfo/right/Asia/Kabul",
            "/usr/share/zoneinfo/right/Asia/Kamchatka",
            "/usr/share/zoneinfo/right/Asia/Karachi",
            "/usr/share/zoneinfo/right/Asia/Kathmandu",
            "/usr/share/zoneinfo/right/Asia/Khandyga",
            "/usr/share/zoneinfo/right/Asia/Kolkata",
            "/usr/share/zoneinfo/right/Asia/Krasnoyarsk",
            "/usr/share/zoneinfo/right/Asia/Kuala_Lumpur",
            "/usr/share/zoneinfo/right/Asia/Kuching",
            "/usr/share/zoneinfo/right/Asia/Kuwait",
            "/usr/share/zoneinfo/right/Asia/Macau",
            "/usr/share/zoneinfo/right/Asia/Magadan",
            "/usr/share/zoneinfo/right/Asia/Makassar",
            "/usr/share/zoneinfo/right/Asia/Manila",
            "/usr/share/zoneinfo/right/Asia/Muscat",
            "/usr/share/zoneinfo/right/Asia/Nicosia",
            "/usr/share/zoneinfo/right/Asia/Novokuznetsk",
            "/usr/share/zoneinfo/right/Asia/Novosibirsk",
            "/usr/share/zoneinfo/right/Asia/Omsk",
            "/usr/share/zoneinfo/right/Asia/Oral",
            "/usr/share/zoneinfo/right/Asia/Phnom_Penh",
            "/usr/share/zoneinfo/right/Asia/Pontianak",
            "/usr/share/zoneinfo/right/Asia/Pyongyang",
            "/usr/share/zoneinfo/right/Asia/Qatar",
            "/usr/share/zoneinfo/right/Asia/Qostanay",
            "/usr/share/zoneinfo/right/Asia/Qyzylorda",
            "/usr/share/zoneinfo/right/Asia/Riyadh",
            "/usr/share/zoneinfo/right/Asia/Sakhalin",
            "/usr/share/zoneinfo/right/Asia/Samarkand",
            "/usr/share/zoneinfo/right/Asia/Seoul",
            "/usr/share/zoneinfo/right/Asia/Shanghai",
            "/usr/share/zoneinfo/right/Asia/Singapore",
            "/usr/share/zoneinfo/right/Asia/Srednekolymsk",
            "/usr/share/zoneinfo/right/Asia/Taipei",
            "/usr/share/zoneinfo/right/Asia/Tashkent",
            "/usr/share/zoneinfo/right/Asia/Tbilisi",
            "/usr/share/zoneinfo/right/Asia/Tehran",
            "/usr/share/zoneinfo/right/Asia/Thimphu",
            "/usr/share/zoneinfo/right/Asia/Tokyo",
            "/usr/share/zoneinfo/right/Asia/Tomsk",
            "/usr/share/zoneinfo/right/Asia/Ulaanbaatar",
            "/usr/share/zoneinfo/right/Asia/Urumqi",
            "/usr/share/zoneinfo/right/Asia/Ust-Nera",
            "/usr/share/zoneinfo/right/Asia/Vientiane",
            "/usr/share/zoneinfo/right/Asia/Vladivostok",
            "/usr/share/zoneinfo/right/Asia/Yakutsk",
            "/usr/share/zoneinfo/right/Asia/Yangon",
            "/usr/share/zoneinfo/right/Asia/Yekaterinburg",
            "/usr/share/zoneinfo/right/Asia/Yerevan",
            "/usr/share/zoneinfo/right/Atlantic/Azores",
            "/usr/share/zoneinfo/right/Atlantic/Bermuda",
            "/usr/share/zoneinfo/right/Atlantic/Canary",
            "/usr/share/zoneinfo/right/Atlantic/Cape_Verde",
            "/usr/share/zoneinfo/right/Atlantic/Faroe",
            "/usr/share/zoneinfo/right/Atlantic/Madeira",
            "/usr/share/zoneinfo/right/Atlantic/Reykjavik",
            "/usr/share/zoneinfo/right/Atlantic/South_Georgia",
            "/usr/share/zoneinfo/right/Atlantic/St_Helena",
            "/usr/share/zoneinfo/right/Atlantic/Stanley",
            "/usr/share/zoneinfo/right/Australia/Adelaide",
            "/usr/share/zoneinfo/right/Australia/Brisbane",
            "/usr/share/zoneinfo/right/Australia/Broken_Hill",
            "/usr/share/zoneinfo/right/Australia/Darwin",
            "/usr/share/zoneinfo/right/Australia/Eucla",
            "/usr/share/zoneinfo/right/Australia/Hobart",
            "/usr/share/zoneinfo/right/Australia/Lindeman",
            "/usr/share/zoneinfo/right/Australia/Lord_Howe",
            "/usr/share/zoneinfo/right/Australia/Melbourne",
            "/usr/share/zoneinfo/right/Australia/Perth",
            "/usr/share/zoneinfo/right/Australia/Sydney",
            "/usr/share/zoneinfo/right/CET",
            "/usr/share/zoneinfo/right/CST6CDT",
            "/usr/share/zoneinfo/right/EET",
            "/usr/share/zoneinfo/right/EST",
            "/usr/share/zoneinfo/right/EST5EDT",
            "/usr/share/zoneinfo/right/Etc/GMT",
            "/usr/share/zoneinfo/right/Etc/GMT+1",
            "/usr/share/zoneinfo/right/Etc/GMT+10",
            "/usr/share/zoneinfo/right/Etc/GMT+11",
            "/usr/share/zoneinfo/right/Etc/GMT+12",
            "/usr/share/zoneinfo/right/Etc/GMT+2",
            "/usr/share/zoneinfo/right/Etc/GMT+3",
            "/usr/share/zoneinfo/right/Etc/GMT+4",
            "/usr/share/zoneinfo/right/Etc/GMT+5",
            "/usr/share/zoneinfo/right/Etc/GMT+6",
            "/usr/share/zoneinfo/right/Etc/GMT+7",
            "/usr/share/zoneinfo/right/Etc/GMT+8",
            "/usr/share/zoneinfo/right/Etc/GMT+9",
            "/usr/share/zoneinfo/right/Etc/GMT-1",
            "/usr/share/zoneinfo/right/Etc/GMT-10",
            "/usr/share/zoneinfo/right/Etc/GMT-11",
            "/usr/share/zoneinfo/right/Etc/GMT-12",
            "/usr/share/zoneinfo/right/Etc/GMT-13",
            "/usr/share/zoneinfo/right/Etc/GMT-14",
            "/usr/share/zoneinfo/right/Etc/GMT-2",
            "/usr/share/zoneinfo/right/Etc/GMT-3",
            "/usr/share/zoneinfo/right/Etc/GMT-4",
            "/usr/share/zoneinfo/right/Etc/GMT-5",
            "/usr/share/zoneinfo/right/Etc/GMT-6",
            "/usr/share/zoneinfo/right/Etc/GMT-7",
            "/usr/share/zoneinfo/right/Etc/GMT-8",
            "/usr/share/zoneinfo/right/Etc/GMT-9",
            "/usr/share/zoneinfo/right/Etc/UTC",
            "/usr/share/zoneinfo/right/Europe/Amsterdam",
            "/usr/share/zoneinfo/right/Europe/Andorra",
            "/usr/share/zoneinfo/right/Europe/Astrakhan",
            "/usr/share/zoneinfo/right/Europe/Athens",
            "/usr/share/zoneinfo/right/Europe/Belgrade",
            "/usr/share/zoneinfo/right/Europe/Berlin",
            "/usr/share/zoneinfo/right/Europe/Brussels",
            "/usr/share/zoneinfo/right/Europe/Bucharest",
            "/usr/share/zoneinfo/right/Europe/Budapest",
            "/usr/share/zoneinfo/right/Europe/Chisinau",
            "/usr/share/zoneinfo/right/Europe/Copenhagen",
            "/usr/share/zoneinfo/right/Europe/Dublin",
            "/usr/share/zoneinfo/right/Europe/Gibraltar",
            "/usr/share/zoneinfo/right/Europe/Guernsey",
            "/usr/share/zoneinfo/right/Europe/Helsinki",
            "/usr/share/zoneinfo/right/Europe/Isle_of_Man",
            "/usr/share/zoneinfo/right/Europe/Istanbul",
            "/usr/share/zoneinfo/right/Europe/Jersey",
            "/usr/share/zoneinfo/right/Europe/Kaliningrad",
            "/usr/share/zoneinfo/right/Europe/Kirov",
            "/usr/share/zoneinfo/right/Europe/Kyiv",
            "/usr/share/zoneinfo/right/Europe/Lisbon",
            "/usr/share/zoneinfo/right/Europe/Ljubljana",
            "/usr/share/zoneinfo/right/Europe/London",
            "/usr/share/zoneinfo/right/Europe/Luxembourg",
            "/usr/share/zoneinfo/right/Europe/Madrid",
            "/usr/share/zoneinfo/right/Europe/Malta",
            "/usr/share/zoneinfo/right/Europe/Minsk",
            "/usr/share/zoneinfo/right/Europe/Monaco",
            "/usr/share/zoneinfo/right/Europe/Moscow",
            "/usr/share/zoneinfo/right/Europe/Oslo",
            "/usr/share/zoneinfo/right/Europe/Paris",
            "/usr/share/zoneinfo/right/Europe/Prague",
            "/usr/share/zoneinfo/right/Europe/Riga",
            "/usr/share/zoneinfo/right/Europe/Rome",
            "/usr/share/zoneinfo/right/Europe/Samara",
            "/usr/share/zoneinfo/right/Europe/Sarajevo",
            "/usr/share/zoneinfo/right/Europe/Saratov",
            "/usr/share/zoneinfo/right/Europe/Simferopol",
            "/usr/share/zoneinfo/right/Europe/Skopje",
            "/usr/share/zoneinfo/right/Europe/Sofia",
            "/usr/share/zoneinfo/right/Europe/Stockholm",
            "/usr/share/zoneinfo/right/Europe/Tallinn",
            "/usr/share/zoneinfo/right/Europe/Tirane",
            "/usr/share/zoneinfo/right/Europe/Ulyanovsk",
            "/usr/share/zoneinfo/right/Europe/Vaduz",
            "/usr/share/zoneinfo/right/Europe/Vienna",
            "/usr/share/zoneinfo/right/Europe/Vilnius",
            "/usr/share/zoneinfo/right/Europe/Volgograd",
            "/usr/share/zoneinfo/right/Europe/Warsaw",
            "/usr/share/zoneinfo/right/Europe/Zagreb",
            "/usr/share/zoneinfo/right/Europe/Zurich",
            "/usr/share/zoneinfo/right/Factory",
            "/usr/share/zoneinfo/right/HST",
            "/usr/share/zoneinfo/right/Indian/Antananarivo",
            "/usr/share/zoneinfo/right/Indian/Chagos",
            "/usr/share/zoneinfo/right/Indian/Christmas",
            "/usr/share/zoneinfo/right/Indian/Cocos",
            "/usr/share/zoneinfo/right/Indian/Comoro",
            "/usr/share/zoneinfo/right/Indian/Kerguelen",
            "/usr/share/zoneinfo/right/Indian/Mahe",
            "/usr/share/zoneinfo/right/Indian/Maldives",
            "/usr/share/zoneinfo/right/Indian/Mauritius",
            "/usr/share/zoneinfo/right/Indian/Mayotte",
            "/usr/share/zoneinfo/right/Indian/Reunion",
            "/usr/share/zoneinfo/right/MET",
            "/usr/share/zoneinfo/right/MST",
            "/usr/share/zoneinfo/right/MST7MDT",
            "/usr/share/zoneinfo/right/PST8PDT",
            "/usr/share/zoneinfo/right/Pacific/Apia",
            "/usr/share/zoneinfo/right/Pacific/Auckland",
            "/usr/share/zoneinfo/right/Pacific/Bougainville",
            "/usr/share/zoneinfo/right/Pacific/Chatham",
            "/usr/share/zoneinfo/right/Pacific/Chuuk",
            "/usr/share/zoneinfo/right/Pacific/Easter",
            "/usr/share/zoneinfo/right/Pacific/Efate",
            "/usr/share/zoneinfo/right/Pacific/Fakaofo",
            "/usr/share/zoneinfo/right/Pacific/Fiji",
            "/usr/share/zoneinfo/right/Pacific/Funafuti",
            "/usr/share/zoneinfo/right/Pacific/Galapagos",
            "/usr/share/zoneinfo/right/Pacific/Gambier",
            "/usr/share/zoneinfo/right/Pacific/Guadalcanal",
            "/usr/share/zoneinfo/right/Pacific/Guam",
            "/usr/share/zoneinfo/right/Pacific/Honolulu",
            "/usr/share/zoneinfo/right/Pacific/Kanton",
            "/usr/share/zoneinfo/right/Pacific/Kiritimati",
            "/usr/share/zoneinfo/right/Pacific/Kosrae",
            "/usr/share/zoneinfo/right/Pacific/Kwajalein",
            "/usr/share/zoneinfo/right/Pacific/Majuro",
            "/usr/share/zoneinfo/right/Pacific/Marquesas",
            "/usr/share/zoneinfo/right/Pacific/Midway",
            "/usr/share/zoneinfo/right/Pacific/Nauru",
            "/usr/share/zoneinfo/right/Pacific/Niue",
            "/usr/share/zoneinfo/right/Pacific/Norfolk",
            "/usr/share/zoneinfo/right/Pacific/Noumea",
            "/usr/share/zoneinfo/right/Pacific/Pago_Pago",
            "/usr/share/zoneinfo/right/Pacific/Palau",
            "/usr/share/zoneinfo/right/Pacific/Pitcairn",
            "/usr/share/zoneinfo/right/Pacific/Pohnpei",
            "/usr/share/zoneinfo/right/Pacific/Port_Moresby",
            "/usr/share/zoneinfo/right/Pacific/Rarotonga",
            "/usr/share/zoneinfo/right/Pacific/Saipan",
            "/usr/share/zoneinfo/right/Pacific/Tahiti",
            "/usr/share/zoneinfo/right/Pacific/Tarawa",
            "/usr/share/zoneinfo/right/Pacific/Tongatapu",
            "/usr/share/zoneinfo/right/Pacific/Wake",
            "/usr/share/zoneinfo/right/Pacific/Wallis",
            "/usr/share/zoneinfo/right/WET",
            "/usr/share/zoneinfo/tzdata.zi",
            "/usr/share/zoneinfo/zone.tab",
            "/usr/share/zoneinfo/zone1970.tab"
          ],
          "AnalyzedBy": "dpkg"
        }
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "DLA-4845-1",
          "VendorIDs": [
            "DLA-4845-1"
          ],
          "PkgID": "ca-certificates@20250419~deb12u1",
          "PkgName": "ca-certificates",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/ca-certificates@20250419~deb12u1?arch=all\u0026distro=debian-12.15",
            "UID": "8dc50e3eef6bbc7d"
          },
          "InstalledVersion": "20250419~deb12u1",
          "FixedVersion": "20250419~deb12u2",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:4db96f2c7ae9e90f3fd5e91cf947d19cced1d8a778d12923113f62c7fff3ec3e",
            "DiffID": "sha256:5904c32f457c96a16c8c68f5ccdf518c8138cd9e5971de9ce6d564fc481af222"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Fingerprint": "sha256:c4d377fffbe45f85d39895413d692586b66bcd79659ca352dceb9f0e6935a5fc",
          "Title": "ca-certificates - security update",
          "Description": "Description Not Available",
          "Severity": "UNKNOWN"
        },
        {
          "VulnerabilityID": "DLA-4792-1",
          "VendorIDs": [
            "DLA-4792-1"
          ],
          "PkgID": "tzdata@2026b-0+deb12u1",
          "PkgName": "tzdata",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all\u0026distro=debian-12.15",
            "UID": "cb2f86311583d698"
          },
          "InstalledVersion": "2026b-0+deb12u1",
          "FixedVersion": "2026c-0+deb12u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:39dc083afc39bd8dc43d456fe7ff7d39292e593bb2769972c11bb2e5f9119386",
            "DiffID": "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Fingerprint": "sha256:d898b74980a919a933ad5bfecb17dedd54a5033c187e64db73ff826654ae3d86",
          "Title": "tzdata - new timezone database",
          "Description": "Description Not Available",
          "Severity": "UNKNOWN"
        },
        {
          "VulnerabilityID": "DLA-4854-1",
          "VendorIDs": [
            "DLA-4854-1"
          ],
          "PkgID": "tzdata@2026b-0+deb12u1",
          "PkgName": "tzdata",
          "PkgIdentifier": {
            "PURL": "pkg:deb/debian/tzdata@2026b-0%2Bdeb12u1?arch=all\u0026distro=debian-12.15",
            "UID": "cb2f86311583d698"
          },
          "InstalledVersion": "2026b-0+deb12u1",
          "FixedVersion": "2026e-0+deb12u1",
          "Status": "fixed",
          "Layer": {
            "Digest": "sha256:39dc083afc39bd8dc43d456fe7ff7d39292e593bb2769972c11bb2e5f9119386",
            "DiffID": "sha256:35b5ba6e08cdd034b8d1920f9c7203e5d66f258e1915f164a01de0af14f34710"
          },
          "DataSource": {
            "ID": "debian",
            "Name": "Debian Security Tracker",
            "URL": "https://salsa.debian.org/security-tracker-team/security-tracker"
          },
          "Fingerprint": "sha256:4772279d3a3cebaef499b143ce2fa1e86d2e58e02ab1bbff0928444dec19cb21",
          "Title": "tzdata - new timezone database",
          "Description": "Description Not Available",
          "Severity": "UNKNOWN"
        }
      ]
    },
    {
      "Target": "ntwire-relay",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Packages": [
        {
          "ID": "github.com/nmaguiar/ntwire@v0.0.0-20261027022619-66fde4fc6548",
          "Name": "github.com/nmaguiar/ntwire",
          "Identifier": {
            "PURL": "pkg:golang/github.com/nmaguiar/ntwire@v0.0.0-20261027022619-66fde4fc6548",
            "UID": "e485ec8ed6c4028"
          },
          "Version": "v0.0.0-20261027022619-66fde4fc6548",
          "Relationship": "root",
          "DependsOn": [
            "github.com/coder/websocket@v1.8.15",
            "github.com/coreos/go-oidc/v3@v3.21.0",
            "github.com/davecgh/go-spew@v1.1.2-0.20180830191138-d8f796af33cc",
            "github.com/emicklei/go-restful/v3@v3.14.0",
            "github.com/fsnotify/fsnotify@v1.10.1",
            "github.com/fxamacker/cbor/v2@v2.9.6",
            "github.com/go-jose/go-jose/v4@v4.1.6",
            "github.com/go-logr/logr@v1.4.4",
            "github.com/go-openapi/jsonpointer@v1.0.2",
            "github.com/go-openapi/jsonreference@v1.0.3",
            "github.com/go-openapi/swag/cmdutils@v0.29.2",
            "github.com/go-openapi/swag/conv@v0.29.2",
            "github.com/go-openapi/swag/fileutils@v0.29.2",
            "github.com/go-openapi/swag/jsonutils@v0.29.2",
            "github.com/go-openapi/swag/loading@v0.29.2",
            "github.com/go-openapi/swag/mangling@v0.29.2",
            "github.com/go-openapi/swag/netutils@v0.29.2",
            "github.com/go-openapi/swag/pools@v0.29.2",
            "github.com/go-openapi/swag/stringutils@v0.29.2",
            "github.com/go-openapi/swag/typeutils@v0.29.2",
            "github.com/go-openapi/swag/yamlutils@v0.29.2",
            "github.com/go-openapi/swag@v0.29.2",
            "github.com/godbus/dbus/v5@v5.2.4",
            "github.com/google/btree@v1.1.3",
            "github.com/google/gnostic-models@v0.7.1",
            "github.com/google/uuid@v1.6.0",
            "github.com/json-iterator/go@v1.1.12",
            "github.com/kayrus/putty@v1.0.5",
            "github.com/modern-go/concurrent@v0.0.0-20180306012644-bacd9c7ef1dd",
            "github.com/modern-go/reflect2@v1.0.3-0.20250322232337-35a7c28c31ee",
            "github.com/munnerz/goautoneg@v0.0.0-20191010083416-a7dc8b61c822",
            "github.com/pmezard/go-difflib@v1.0.1-0.20181226105442-5d4384ee4fb2",
            "github.com/x448/float16@v0.8.4",
            "github.com/youmark/pkcs8@v0.0.0-20240726163527-a2c0da244d78",
            "github.com/zalando/go-keyring@v0.2.8",
            "go.yaml.in/yaml/v2@v2.4.4",
            "go.yaml.in/yaml/v3@v3.0.5",
            "golang.org/x/crypto@v0.58.0",
            "golang.org/x/net@v0.61.0",
            "golang.org/x/oauth2@v0.37.0",
            "golang.org/x/sys@v0.49.0",
            "golang.org/x/term@v0.47.0",
            "golang.org/x/text@v0.43.0",
            "golang.org/x/time@v0.16.0",
            "golang.zx2c4.com/wireguard@v0.0.0-20261024220952-b3bc704ef0ee",
            "google.golang.org/protobuf@v1.36.12",
            "gopkg.in/evanphx/json-patch.v4@v4.13.0",
            "gopkg.in/inf.v0@v0.9.1",
            "gopkg.in/yaml.v3@v3.0.1",
            "gvisor.dev/gvisor@v0.0.0-20250503011706-39ed1f5ac29c",
            "k8s.io/api@v0.37.1",
            "k8s.io/apimachinery@v0.37.1",
            "k8s.io/client-go@v0.37.1",
            "k8s.io/klog/v2@v2.140.0",
            "k8s.io/kube-openapi@v0.0.0-20260721132016-d427ff9ee9ad",
            "k8s.io/utils@v0.0.0-20261023123148-ca04ba58ecab",
            "sigs.k8s.io/json@v0.0.0-20260909141634-11ed52e25bc5",
            "sigs.k8s.io/randfill@v1.0.0",
            "sigs.k8s.io/structured-merge-diff/v6@v6.4.2",
            "sigs.k8s.io/yaml@v1.6.0",
            "stdlib@v1.27.3"
          ],
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "stdlib@v1.27.3",
          "Name": "stdlib",
          "Identifier": {
            "PURL": "pkg:golang/stdlib@v1.27.3",
            "UID": "895ddb59296b0b5e"
          },
          "Version": "v1.27.3",
          "Relationship": "direct",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/coder/websocket@v1.8.15",
          "Name": "github.com/coder/websocket",
          "Identifier": {
            "PURL": "pkg:golang/github.com/coder/websocket@v1.8.15",
            "UID": "3e0c05436ea8cb7d"
          },
          "Version": "v1.8.15",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/coreos/go-oidc/v3@v3.21.0",
          "Name": "github.com/coreos/go-oidc/v3",
          "Identifier": {
            "PURL": "pkg:golang/github.com/coreos/go-oidc/v3@v3.21.0",
            "UID": "ad27f7601cce9977"
          },
          "Version": "v3.21.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/davecgh/go-spew@v1.1.2-0.20180830191138-d8f796af33cc",
          "Name": "github.com/davecgh/go-spew",
          "Identifier": {
            "PURL": "pkg:golang/github.com/davecgh/go-spew@v1.1.2-0.20180830191138-d8f796af33cc",
            "UID": "68ad52b964db3fc1"
          },
          "Version": "v1.1.2-0.20180830191138-d8f796af33cc",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/emicklei/go-restful/v3@v3.14.0",
          "Name": "github.com/emicklei/go-restful/v3",
          "Identifier": {
            "PURL": "pkg:golang/github.com/emicklei/go-restful/v3@v3.14.0",
            "UID": "f7864cdbc5b40e20"
          },
          "Version": "v3.14.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/fsnotify/fsnotify@v1.10.1",
          "Name": "github.com/fsnotify/fsnotify",
          "Identifier": {
            "PURL": "pkg:golang/github.com/fsnotify/fsnotify@v1.10.1",
            "UID": "7377de1fb6e78ab8"
          },
          "Version": "v1.10.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/fxamacker/cbor/v2@v2.9.6",
          "Name": "github.com/fxamacker/cbor/v2",
          "Identifier": {
            "PURL": "pkg:golang/github.com/fxamacker/cbor/v2@v2.9.6",
            "UID": "849d591986d915a3"
          },
          "Version": "v2.9.6",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-jose/go-jose/v4@v4.1.6",
          "Name": "github.com/go-jose/go-jose/v4",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-jose/go-jose/v4@v4.1.6",
            "UID": "e654da34f698392c"
          },
          "Version": "v4.1.6",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-logr/logr@v1.4.4",
          "Name": "github.com/go-logr/logr",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-logr/logr@v1.4.4",
            "UID": "cd285b3ca2e22a57"
          },
          "Version": "v1.4.4",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/jsonpointer@v1.0.2",
          "Name": "github.com/go-openapi/jsonpointer",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/jsonpointer@v1.0.2",
            "UID": "1a066f74c6a5dda4"
          },
          "Version": "v1.0.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/jsonreference@v1.0.3",
          "Name": "github.com/go-openapi/jsonreference",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/jsonreference@v1.0.3",
            "UID": "466552744f251807"
          },
          "Version": "v1.0.3",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag@v0.29.2",
          "Name": "github.com/go-openapi/swag",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag@v0.29.2",
            "UID": "a81c3d2935504c60"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/cmdutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/cmdutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/cmdutils@v0.29.2",
            "UID": "c0b71a18b02017ad"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/conv@v0.29.2",
          "Name": "github.com/go-openapi/swag/conv",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/conv@v0.29.2",
            "UID": "f5cf2575d5376c9c"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/fileutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/fileutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/fileutils@v0.29.2",
            "UID": "93b5a9fd1f90d50e"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/jsonutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/jsonutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/jsonutils@v0.29.2",
            "UID": "da44241ac4f878c4"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/loading@v0.29.2",
          "Name": "github.com/go-openapi/swag/loading",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/loading@v0.29.2",
            "UID": "32b3bc395a59cac4"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/mangling@v0.29.2",
          "Name": "github.com/go-openapi/swag/mangling",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/mangling@v0.29.2",
            "UID": "abd3e20af77555ae"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/netutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/netutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/netutils@v0.29.2",
            "UID": "730deb2f500b9655"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/pools@v0.29.2",
          "Name": "github.com/go-openapi/swag/pools",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/pools@v0.29.2",
            "UID": "f4792d9788cf5f36"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/stringutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/stringutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/stringutils@v0.29.2",
            "UID": "849c3d380fd63d4b"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/typeutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/typeutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/typeutils@v0.29.2",
            "UID": "407e5ca152bf89a2"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/go-openapi/swag/yamlutils@v0.29.2",
          "Name": "github.com/go-openapi/swag/yamlutils",
          "Identifier": {
            "PURL": "pkg:golang/github.com/go-openapi/swag/yamlutils@v0.29.2",
            "UID": "7ddcf6d4511e02a4"
          },
          "Version": "v0.29.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/godbus/dbus/v5@v5.2.4",
          "Name": "github.com/godbus/dbus/v5",
          "Identifier": {
            "PURL": "pkg:golang/github.com/godbus/dbus/v5@v5.2.4",
            "UID": "898ea1577bfb6d44"
          },
          "Version": "v5.2.4",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/google/btree@v1.1.3",
          "Name": "github.com/google/btree",
          "Identifier": {
            "PURL": "pkg:golang/github.com/google/btree@v1.1.3",
            "UID": "5f034e18418e854d"
          },
          "Version": "v1.1.3",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/google/gnostic-models@v0.7.1",
          "Name": "github.com/google/gnostic-models",
          "Identifier": {
            "PURL": "pkg:golang/github.com/google/gnostic-models@v0.7.1",
            "UID": "b4a3a77296131570"
          },
          "Version": "v0.7.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/google/uuid@v1.6.0",
          "Name": "github.com/google/uuid",
          "Identifier": {
            "PURL": "pkg:golang/github.com/google/uuid@v1.6.0",
            "UID": "bb80dab333d5dfff"
          },
          "Version": "v1.6.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/json-iterator/go@v1.1.12",
          "Name": "github.com/json-iterator/go",
          "Identifier": {
            "PURL": "pkg:golang/github.com/json-iterator/go@v1.1.12",
            "UID": "28bc007d9decd4a5"
          },
          "Version": "v1.1.12",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/kayrus/putty@v1.0.5",
          "Name": "github.com/kayrus/putty",
          "Identifier": {
            "PURL": "pkg:golang/github.com/kayrus/putty@v1.0.5",
            "UID": "a2eabfe75a2e19cd"
          },
          "Version": "v1.0.5",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/modern-go/concurrent@v0.0.0-20180306012644-bacd9c7ef1dd",
          "Name": "github.com/modern-go/concurrent",
          "Identifier": {
            "PURL": "pkg:golang/github.com/modern-go/concurrent@v0.0.0-20180306012644-bacd9c7ef1dd",
            "UID": "aa948de8a01e6b3b"
          },
          "Version": "v0.0.0-20180306012644-bacd9c7ef1dd",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/modern-go/reflect2@v1.0.3-0.20250322232337-35a7c28c31ee",
          "Name": "github.com/modern-go/reflect2",
          "Identifier": {
            "PURL": "pkg:golang/github.com/modern-go/reflect2@v1.0.3-0.20250322232337-35a7c28c31ee",
            "UID": "b30b25c7fae2b38b"
          },
          "Version": "v1.0.3-0.20250322232337-35a7c28c31ee",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/munnerz/goautoneg@v0.0.0-20191010083416-a7dc8b61c822",
          "Name": "github.com/munnerz/goautoneg",
          "Identifier": {
            "PURL": "pkg:golang/github.com/munnerz/goautoneg@v0.0.0-20191010083416-a7dc8b61c822",
            "UID": "8bb7f5e27c16b5f1"
          },
          "Version": "v0.0.0-20191010083416-a7dc8b61c822",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/pmezard/go-difflib@v1.0.1-0.20181226105442-5d4384ee4fb2",
          "Name": "github.com/pmezard/go-difflib",
          "Identifier": {
            "PURL": "pkg:golang/github.com/pmezard/go-difflib@v1.0.1-0.20181226105442-5d4384ee4fb2",
            "UID": "d46874c3afb1ffd9"
          },
          "Version": "v1.0.1-0.20181226105442-5d4384ee4fb2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/x448/float16@v0.8.4",
          "Name": "github.com/x448/float16",
          "Identifier": {
            "PURL": "pkg:golang/github.com/x448/float16@v0.8.4",
            "UID": "fad1a6fcb1e87893"
          },
          "Version": "v0.8.4",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/youmark/pkcs8@v0.0.0-20240726163527-a2c0da244d78",
          "Name": "github.com/youmark/pkcs8",
          "Identifier": {
            "PURL": "pkg:golang/github.com/youmark/pkcs8@v0.0.0-20240726163527-a2c0da244d78",
            "UID": "fd2294c7446ffb9"
          },
          "Version": "v0.0.0-20240726163527-a2c0da244d78",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "github.com/zalando/go-keyring@v0.2.8",
          "Name": "github.com/zalando/go-keyring",
          "Identifier": {
            "PURL": "pkg:golang/github.com/zalando/go-keyring@v0.2.8",
            "UID": "466bba8b8c4eb2c"
          },
          "Version": "v0.2.8",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "go.yaml.in/yaml/v2@v2.4.4",
          "Name": "go.yaml.in/yaml/v2",
          "Identifier": {
            "PURL": "pkg:golang/go.yaml.in/yaml/v2@v2.4.4",
            "UID": "30eae1adb0e94454"
          },
          "Version": "v2.4.4",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "go.yaml.in/yaml/v3@v3.0.5",
          "Name": "go.yaml.in/yaml/v3",
          "Identifier": {
            "PURL": "pkg:golang/go.yaml.in/yaml/v3@v3.0.5",
            "UID": "b612541495bd7a51"
          },
          "Version": "v3.0.5",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/crypto@v0.58.0",
          "Name": "golang.org/x/crypto",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/crypto@v0.58.0",
            "UID": "3603b6a81b9f985f"
          },
          "Version": "v0.58.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/net@v0.61.0",
          "Name": "golang.org/x/net",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/net@v0.61.0",
            "UID": "54783f910b0f48d5"
          },
          "Version": "v0.61.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/oauth2@v0.37.0",
          "Name": "golang.org/x/oauth2",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/oauth2@v0.37.0",
            "UID": "105493e6df6ef520"
          },
          "Version": "v0.37.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/sys@v0.49.0",
          "Name": "golang.org/x/sys",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/sys@v0.49.0",
            "UID": "59f49ed53ff034bf"
          },
          "Version": "v0.49.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/term@v0.47.0",
          "Name": "golang.org/x/term",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/term@v0.47.0",
            "UID": "43661d1daf80595c"
          },
          "Version": "v0.47.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/text@v0.43.0",
          "Name": "golang.org/x/text",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/text@v0.43.0",
            "UID": "c2a732deb609483"
          },
          "Version": "v0.43.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.org/x/time@v0.16.0",
          "Name": "golang.org/x/time",
          "Identifier": {
            "PURL": "pkg:golang/golang.org/x/time@v0.16.0",
            "UID": "c7534c17c1534f52"
          },
          "Version": "v0.16.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "golang.zx2c4.com/wireguard@v0.0.0-20261024220952-b3bc704ef0ee",
          "Name": "golang.zx2c4.com/wireguard",
          "Identifier": {
            "PURL": "pkg:golang/golang.zx2c4.com/wireguard@v0.0.0-20261024220952-b3bc704ef0ee",
            "UID": "9f28048dd58b8163"
          },
          "Version": "v0.0.0-20261024220952-b3bc704ef0ee",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "google.golang.org/protobuf@v1.36.12",
          "Name": "google.golang.org/protobuf",
          "Identifier": {
            "PURL": "pkg:golang/google.golang.org/protobuf@v1.36.12",
            "UID": "e6a19809575b766e"
          },
          "Version": "v1.36.12",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "gopkg.in/evanphx/json-patch.v4@v4.13.0",
          "Name": "gopkg.in/evanphx/json-patch.v4",
          "Identifier": {
            "PURL": "pkg:golang/gopkg.in/evanphx/json-patch.v4@v4.13.0",
            "UID": "d8e8ddfa292bf0da"
          },
          "Version": "v4.13.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "gopkg.in/inf.v0@v0.9.1",
          "Name": "gopkg.in/inf.v0",
          "Identifier": {
            "PURL": "pkg:golang/gopkg.in/inf.v0@v0.9.1",
            "UID": "cd7f2cd4e82ba1b"
          },
          "Version": "v0.9.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "gopkg.in/yaml.v3@v3.0.1",
          "Name": "gopkg.in/yaml.v3",
          "Identifier": {
            "PURL": "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
            "UID": "b4e390f4aced1e59"
          },
          "Version": "v3.0.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "gvisor.dev/gvisor@v0.0.0-20250503011706-39ed1f5ac29c",
          "Name": "gvisor.dev/gvisor",
          "Identifier": {
            "PURL": "pkg:golang/gvisor.dev/gvisor@v0.0.0-20250503011706-39ed1f5ac29c",
            "UID": "e1864efc2c0fe7e9"
          },
          "Version": "v0.0.0-20250503011706-39ed1f5ac29c",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/api@v0.37.1",
          "Name": "k8s.io/api",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/api@v0.37.1",
            "UID": "df4d8c8c145f1807"
          },
          "Version": "v0.37.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/apimachinery@v0.37.1",
          "Name": "k8s.io/apimachinery",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/apimachinery@v0.37.1",
            "UID": "3da0acc02255d7db"
          },
          "Version": "v0.37.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/client-go@v0.37.1",
          "Name": "k8s.io/client-go",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/client-go@v0.37.1",
            "UID": "1d2002b7f4a204c0"
          },
          "Version": "v0.37.1",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/klog/v2@v2.140.0",
          "Name": "k8s.io/klog/v2",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/klog/v2@v2.140.0",
            "UID": "c5c1a5021fb4f414"
          },
          "Version": "v2.140.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/kube-openapi@v0.0.0-20260721132016-d427ff9ee9ad",
          "Name": "k8s.io/kube-openapi",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/kube-openapi@v0.0.0-20260721132016-d427ff9ee9ad",
            "UID": "735f3ba069138c4c"
          },
          "Version": "v0.0.0-20260721132016-d427ff9ee9ad",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "k8s.io/utils@v0.0.0-20261023123148-ca04ba58ecab",
          "Name": "k8s.io/utils",
          "Identifier": {
            "PURL": "pkg:golang/k8s.io/utils@v0.0.0-20261023123148-ca04ba58ecab",
            "UID": "65fb867fd68af1c5"
          },
          "Version": "v0.0.0-20261023123148-ca04ba58ecab",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "sigs.k8s.io/json@v0.0.0-20260909141634-11ed52e25bc5",
          "Name": "sigs.k8s.io/json",
          "Identifier": {
            "PURL": "pkg:golang/sigs.k8s.io/json@v0.0.0-20260909141634-11ed52e25bc5",
            "UID": "22978819f069c26c"
          },
          "Version": "v0.0.0-20260909141634-11ed52e25bc5",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "sigs.k8s.io/randfill@v1.0.0",
          "Name": "sigs.k8s.io/randfill",
          "Identifier": {
            "PURL": "pkg:golang/sigs.k8s.io/randfill@v1.0.0",
            "UID": "eef94ed41a70b5d4"
          },
          "Version": "v1.0.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "sigs.k8s.io/structured-merge-diff/v6@v6.4.2",
          "Name": "sigs.k8s.io/structured-merge-diff/v6",
          "Identifier": {
            "PURL": "pkg:golang/sigs.k8s.io/structured-merge-diff/v6@v6.4.2",
            "UID": "ea8a3dcbda45c4a4"
          },
          "Version": "v6.4.2",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        },
        {
          "ID": "sigs.k8s.io/yaml@v1.6.0",
          "Name": "sigs.k8s.io/yaml",
          "Identifier": {
            "PURL": "pkg:golang/sigs.k8s.io/yaml@v1.6.0",
            "UID": "6835227046cccccf"
          },
          "Version": "v1.6.0",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "AnalyzedBy": "gobinary"
        }
      ],
      "Vulnerabilities": [
        {
          "VulnerabilityID": "GO-2026-5932",
          "PkgID": "golang.org/x/crypto@v0.58.0",
          "PkgName": "golang.org/x/crypto",
          "PkgIdentifier": {
            "PURL": "pkg:golang/golang.org/x/crypto@v0.58.0",
            "UID": "3603b6a81b9f985f"
          },
          "InstalledVersion": "v0.58.0",
          "Status": "affected",
          "Layer": {
            "Digest": "sha256:ec8178891ef92a1bf8745fec5f8bd13059ffce7fec9291549c965afcc5fd96c1",
            "DiffID": "sha256:a5cbc7805351d9b629e4ab3966e5ff5933ce5531c0235cd9a7ec0c0cceb4b3fc"
          },
          "DataSource": {
            "ID": "govulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://pkg.go.dev/vuln/"
          },
          "Fingerprint": "sha256:636067106a536802cc79a4c18e66a458961504577536333cd7bedb59738b1a9f",
          "Title": "The golang.org/x/crypto/openpgp package is unmaintained, unsafe by design, and has known security issues",
          "Description": "The golang.org/x/crypto/openpgp package is unsafe by design, has numerous known security issues, is not maintained, and should not be used.\n\nIf you are required to interoperate with OpenPGP systems and need a maintained package, consider github.com/ProtonMail/go-crypto/openpgp which is a maintained fork that aims to be a drop-in replacement for this package.",
          "Severity": "UNKNOWN",
          "References": [
            "https://go.dev/issue/44226",
            "https://pkg.go.dev/vuln/GO-2026-5932"
          ]
        }
      ]
    }
  ]
}
```
</details>
