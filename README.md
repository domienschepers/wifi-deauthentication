# Wi-Fi Deauthentication

In this repository, we present deauthentication techniques bypassing Wi-Fi Management Frame Protection.

This leads to denial-of-service, and can help an adversary to execute other attacks (for example, when a new handshake is required).

We share proof-of-concept code, and provide an overview of available security patches and updates.

#### Wi-Fi Management Frame Protection

Wi-Fi Management Frame Protection (MFP) protects robust management frames by providing data confidentiality, integrity, origin authenticity, and replay protection.
One of its key goals is to prevent deauthentication attacks in which an adversary forcibly disconnects a client from the network.

## Vulnerabilities

We identified the following vulnerabilities, disconnecting the client and access point.

#### 4-Way Handshake 

| Vulnerability | hostap-2.9 | hostap-2.10 | iwd-1.27 |
| :--- | :---: | :---: | :---: |
| Corrrupt 4-Way Handshake Message 1/4 | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |

| Vulnerability | Android 12 |
| :--- | :---: |
| Incorrect IGTK Installation | :heavy_check_mark: |

#### IEEE 802.1X Authentication

| Vulnerability | hostap-2.9 | hostap-2.10 | iwd-1.27 |
| :--- | :---: | :---: | :---: |
| EAPoL Logoff | :heavy_check_mark: | :heavy_check_mark: | |
| EAP Failure | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark:<sup>1 |
| Maximum Number of EAP Rounds | :heavy_check_mark: | :heavy_check_mark: | |
| Maximum Number of Re-Authentications | :heavy_check_mark: | :heavy_check_mark: | |

<sup>1</sup> Also successful against personal network configurations such as WPA3-Personal.

#### MLME Processing

| Vulnerability | Linux 5.15.0 | macOS 12.3 | iOS 15.4 |
| :--- | :---: | :---: | :---: |
| Invalid Channel Switch Announcement | :heavy_check_mark: | :heavy_check_mark: | :heavy_check_mark: |
| Unsupported Bandwidth Change | :heavy_check_mark: | | |

## Proof-of-Concept

Proof-of-concepts are available in [test-deauthentication.py](test-deauthentication.py).
  
Note that currently not all proof-of-concepts are available due to ongoing disclosures and security updates.

These proof-of-concepts are implemented using the [Wi-Fi Framework](https://github.com/domienschepers/wifi-framework).

## Security Updates and Patches

The [Pixel Update Bulletin](https://source.android.com/docs/security/bulletin/pixel/2023-03-01) of March 2023 addressed the IGTK vulnerability (CVE-2023-21061).

Patches were applied to ensure EAPOL-Key frames containing invalid field values are silently discarded:

| | Patch |
| :--- | :--- |
| hostap | [WPA: Discard EAPOL-Key msg 1/4 with corrupted information elements](https://w1.fi/cgit/hostap/commit/?id=b1172c19e1900d478f98437fdf8114a5d5a81b0c) |
| IWD | [[PATCH] eapol: Silently discard invalid EAPoL frames](https://lists.01.org/hyperkitty/list/iwd@lists.01.org/thread/5KQ2CCOBWEY7AT57YGECFKCHYHOWKUF6/) |

## Publication

ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec 2022):

- On the Robustness of Wi-Fi Deauthentication Countermeasures ([pdf](https://aanjhan.com/assets/schepers22wisec.pdf), [acm](https://dl.acm.org/doi/abs/10.1145/3507657.3528548))
