# Wi-Fi Framing

This repository summarizes information for the *'Framing Frames'* publication at [USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers) ([pdf](https://papers.mathyvanhoef.com/usenix2023-wifi.pdf)).

## MacStealer: Wi-Fi Client Isolation Bypass

The [MacStealer](https://github.com/vanhoefm/macstealer) repository provides a tool to test Wi-Fi networks for **client isolation bypasses (CVE-2022-47522). Our attack can intercept (steal) traffic toward other clients at the MAC layer**, even if clients are prevented from communicating with each other.

Detailed information is available on the [MacStealer: Wi-Fi Client Isolation Bypass](https://github.com/vanhoefm/macstealer) repository.

## Security Advisories

The Wi-Fi Alliance and affected parties were informed on all discovered issues.

At the time of writing, the following security advisories are available:

- [Cisco Security Advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wifi-ffeb-22epcEWu), *"Framing Frames (...) Affecting Multiple Cisco Products"*.
- [Ubiquiti](https://community.ui.com/releases/airMAX-M-6-3-10/2bb93457-7a7c-4edf-ade4-3c200fcf1808) airMAX M, *"Security workaround for CVE-2022-47522"*.
- [LANCOM Systems](https://www.lancom-systems.com/service-support/general-security-information), *"Information regarding the paper „Framing Frames“ ([Knowledge Base](https://support.lancom-systems.com/knowledge/pages/viewpage.action?pageId=132776273))"*.
- [Aruba Product Security Advisory](https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2023-005.txt), *"All currently supported ArubaOS (...) versions are affected"*.
- [Mist Security Advisory](https://www.mist.com/documentation/mist-security-advisory-bypassing-wi-fi-encryption-by-manipulating-transmit-queues/), *"Clients connecting to Mist Access Points could be targeted with this attack"*.
- [Ruckus Networks](https://support.ruckuswireless.com/security_bulletins/317), *"Security Bulletin for CVE-2022-47522"*.

## Talks

Parts of this work are presented at the following symposiums and industry conferences.

Real World Crypto 2023:
- [Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues](https://rwc.iacr.org/2023/program.php)

Centre for Cybersecurity Belgium | Connect & Share 2023:
- [The State of Wi-Fi Security and Vulnerabilities in Client Isolation](https://app.livestorm.co/ccb/centre-for-cybersecurity-belgium-ccb-connect-and-share-event-qctr)

Black Hat Asia 2023:
- [Sweet Dreams: Abusing Sleep Mode to Break Wi-Fi Encryption and Disrupt WPA2/3 Networks](https://www.blackhat.com/asia-23/briefings/schedule/index.html#sweet-dreams-abusing-sleep-mode-to-break-wi-fi-encryption-and-disrupt-wpa-networks-30942)


## Publication

This work is published at [USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers).

#### Title

Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues ([pdf](https://papers.mathyvanhoef.com/usenix2023-wifi.pdf))

#### Abstract

Wi-Fi devices routinely queue frames at various layers of the network stack before transmitting, for instance, when the receiver is in sleep mode.
In this work, we investigate how Wi-Fi access points manage the security context of queued frames.
By exploiting power-save features, we show how to trick access points into leaking frames in plaintext, or encrypted using the group or an all-zero key.
We demonstrate resulting attacks against several open-source network stacks.
We attribute our findings to the lack of explicit guidance in managing security contexts of buffered frames in the 802.11 standards.
The unprotected nature of the power-save bit in a frame’s header, which our work reveals to be a fundamental design flaw, also allows an adversary to force queue frames intended for a specific client resulting in its disconnection and trivially executing a denial-of-service attack.

Furthermore, we demonstrate how an attacker can override and control the security context of frames that are yet to be queued.
This exploits a design flaw in hotspot-like networks and allows the attacker to force an access point to encrypt yet to be queued frames using an adversary-chosen key, thereby bypassing Wi-Fi encryption entirely.

Our attacks have a widespread impact as they affect various devices and operating systems (Linux, FreeBSD, iOS, and Android) and because they can be used to hijack TCP connections or intercept client and web traffic.
Overall, we highlight the need for transparency in handling security context across the network stack layers and the challenges in doing so.

#### BibTeX

```bibtex
@inproceedings{schepers2023framing,
  title={Framing Frames: Bypassing {Wi-Fi} Encryption by Manipulating Transmit Queues},
  author={Schepers, Domien and Ranganathan, Aanjhan and Vanhoef, Mathy},
  booktitle={32nd USENIX Security Symposium (USENIX Security 23)},
  year={2023}
}
```
