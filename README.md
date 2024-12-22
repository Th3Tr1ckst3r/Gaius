<p align="center">
  <img src="https://i.imgur.com/KbEfnzA.jpeg" alt="Gaius Logo" width="300">
</p>

# Gaius

[![License](https://img.shields.io/badge/License-GPL%203.0%20with%20AGPL%203.0-blue.svg)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Th3Tr1ckst3r/Gaius)](https://github.com/Th3Tr1ckst3r/Gaius/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Th3Tr1ckst3r/Gaius)](https://github.com/Th3Tr1ckst3r/Gaius/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/Th3Tr1ckst3r/Gaius)](https://github.com/Th3Tr1ckst3r/Gaius/issues)

A cryptography tool which implements a new complex mixed substitution cipher dubbed **"Gaius Cipher"** into binary/plaintext data structures. 

## About

As the name suggests, Gaius Julius Caesar (the Elder) was the father of Julius Caesar, who is often credited with laying the foundation of cryptography in its earliest documented form through his use of the Caesar cipher. While Gaius played a significant role in Julius Caesar's early life, providing him with a patrician lineage and moral guidance, his untimely passing thrust Julius into the position of family head at the age of 16. From this point, Julius began his rise to prominence, eventually becoming one of the most influential figures in Roman history.

Inspired by the renowned **Caesar cipher**, the **"Gaius cipher"** emerged as a sophisticated approach. While the Caesar cipher operates as a simple monoalphabetic substitution cipher, the **"Gaius cipher"** introduces a hybrid approach, blending classical substitution techniques with modern encoding features. Making it both versatile, & fairly secure.

## Why Use Gaius, or **"Gaius Cipher"**?

The **"Gaius cipher"** offers a unique balance between simplicity, and modern security. Making it an excellent choice for a variety of cryptographic needs. Traditional ciphers, which are often either too simplistic, or overly complex. The **"Gaius cipher"** integrates the straightforward logic of classical substitution with the robustness of contemporary encoding techniques. This hybrid design ensures not only ease of implementation, but also enhanced resistance to common cryptographic attacks. Whether you are a student learning about encryption, a developer seeking a lightweight cipher for embedded systems, or a cryptography enthusiast exploring innovative designs. The **"Gaius cipher"** provides an ideal blend of functionality, adaptability, and security.

## Features

- **Hybrid Design**: Combines classical monoalphabetic substitution with modern encoding techniques for enhanced security.
- **Enhanced Resistance**: Provides improved defense against common cryptographic attacks compared to traditional ciphers.
- **Simplicity**: Easy to implement and understand, making it accessible for beginners and experts alike.
- **Customizability**: Offers flexibility to adjust parameters, tailoring it to specific cryptographic needs.
- **Efficiency**: Lightweight design ensures quick encryption and decryption processes, suitable for resource-constrained environments.
- **Educational Value**: Serves as a practical tool for learning cryptographic principles and exploring hybrid encryption methods.
- **Versatility**: Adaptable for use in various applications, from embedded systems to experimental cryptography projects.

## Screenshots

This is the command line(CLI) interface for Gaius. Its meant to be easy, & minimal.

![Gaius_CLI](https://i.imgur.com/JX4oa5j.png)

## Installation Notices

- **Cipher vs. Encoding**: **Gaius** is a cipher, meaning it obfuscates data to secure its content. It is not encryption in the modern sense; encoding focuses on data representation, while ciphers focus on securing the message's meaning.

- **Not a Replacement for Strong Encryption**: **Gaius** is a hybrid monoalphabetic substitution cipher, which can provide a layer of security but should not be used as a substitute for robust encryption algorithms like AES or RSA in critical applications.

- **Susceptible to Frequency Analysis**: Like other substitution ciphers, **Gaius** is **vulnerable** to frequency analysis if the ciphertext is long enough, as patterns in plaintext can translate into patterns in ciphertext.

- **Key Management**: The security of **Gaius** relies heavily on keeping the password/keyword secure. If the password/keyword is leaked, the cipher is rendered ineffective.

- **Limited Resistance to Advanced Attacks**: Modern cryptanalysis techniques, such as chosen plaintext attacks or brute-force attempts, can exploit its weaknesses, especially if the cipher uses predictable or static components.

- **Ciphertext Length**: **Gaius** may not obfuscate the length of the plaintext, which could provide additional information to attackers. Use padding, or additional layers to mitigate this.

- **No Built-in Integrity Verification**: **Gaius** does not include mechanisms to ensure the integrity of the ciphertext, leaving it open to tampering without detection. Combine it with a hash or checksum for added protection.

- **Not Secure for Sensitive Data**: Due to its susceptibility to basic cryptographic attacks, **Gaius** is best suited for educational purposes or low-stakes applications, rather than for securing highly sensitive or classified information.

- **Customizability Risks**: While its flexibility is an advantage, improper configuration can inadvertently weaken the cipher, making it easier for attackers to break.

- **Complement, Don’t Replace**: Use **Gaius** as a complementary layer to modern encryption techniques rather than relying on it as the sole means of securing data.

## Notes

**Gaius** does perform basic password validation for enhanced protection, & to ensure users use good password/keyword practices. This tool can also be useful in conjunction with payloads that use base64, or in CTF's. If you dont feel comfortable using the provided Linux binary release, you can also generate it from the source code provided with GCC compiler, or other compiler of your choice.

## Contributors
<a name="Contributors"></a>

<p align="center">
    <a href="https://github.com/Th3Tr1ckst3r"><img src="https://avatars.githubusercontent.com/u/21149460?v=4" width=75 height=75></a>
</p>


I welcome you to contribute code to **Gaius**, and thank you for your contributions, feedback, and support.

