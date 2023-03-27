# Wi-Fi Framing

This repository summarizes information for the *'Framing Frames'* publication at [USENIX Security 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/schepers) ([pdf](https://papers.mathyvanhoef.com/usenix2023-wifi.pdf)).

## MacStealer: Wi-Fi Client Isolation Bypass

The [MacStealer](https://github.com/vanhoefm/macstealer) repository provides a tool to test Wi-Fi networks for **client isolation bypasses (CVE-2022-47522). Our attack can intercept (steal) traffic toward other clients at the MAC layer**, even if clients are prevented from communicating with each other.

Detailed information is available on the [MacStealer: Wi-Fi Client Isolation Bypass](https://github.com/vanhoefm/macstealer) repository.

## Security Advisories

The Wi-Fi Alliance and affected parties were informed on all discovered issues.

Once publicly available, we will list an overview of security advisories here.

## Talks

Parts of this work are presented at the following symposiums and industry conferences.

Real World Crypto 2023:
- [Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues](https://rwc.iacr.org/2023/program.php)

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
