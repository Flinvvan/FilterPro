<div align="center">
    <img src="https://github.com/Flinvvan/FilterPro/blob/main/biglogo.png" alt="FilterPro Logo" style="display: block; margin: 0 auto;" />


  [![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Plugin-orange?style=flat-square&logo=burpsuite&logoColor=white)](https://portswigger.net/burp)
  [![Burp Version](https://img.shields.io/badge/Burp%20Version-2023.12.1%2B-9cf?style=flat-square)](https://portswigger.net/burp)
  [![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
  [![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square)](https://github.com/Flinvvan/FilterPro/releases)

</div>

---

## 📋 Project Introduction

**FilterPro** is a noise packet filtering extension specifically designed for **Burp Suite**, helping you eliminate traffic noise during testing and allowing you to focus on analyzing critical requests. Working in conjunction with Burp's **History Filter** feature, it efficiently filters out the following distractions:

- ❤️ Heartbeat packets / Health checks
- 📜 Application log requests
- 🌐 Browser background miscellaneous requests
- ⚙️ Meaningless `OPTIONS` preflight requests
- 🔔 Any other domains or requests you don't want to see

From now on, your Burp Suite will only contain the business traffic that requires focused analysis!

## 📥 Installation

### Prerequisites
- **Burp Suite Professional/Community version**: >= 2023.12.1

### Installation Steps
1. **Download the extension**: [FilterPro.jar](https://github.com/Flinvvan/FilterPro/releases/tag/1.0.0)
2. **Load the extension in Burp**: **Extensions --> Add --> Java --> Select file --> FilterPro --> Next**

![image-20260124151608957](https://github.com/Flinvvan/FilterPro/blob/main/images/0.png)

> 💡 **Tip**: The demonstration above is based on Burp Suite v2025.5. The process is similar for other versions.

## ✨ Features

### 1. Generate Filtering Rules

FilterPro provides multiple intuitive ways to generate rules to adapt to different filtering scenarios.

![image-20260124145303449](https://github.com/Flinvvan/FilterPro/blob/main/images/1.png)

| Rule Type           | Suitable Scenario                                               | Example/Explanation                                           |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------- |
| **API-based**       | Filter fixed interfaces, suitable for requests with few parameters and no dynamic changes (like timestamps). | Directly input the API path, e.g., `/api/heartbeat`.          |
| **Host-based**      | Filter all traffic from an entire domain or subdomain.         | Supports wildcards, e.g., traffic from `*.bing.com`, `*.google.com`. |
| **Method-based**    | Quickly filter requests by specific HTTP methods, such as the common nuisance `OPTIONS`. | Check the `OPTIONS` method to generate the rule with one click. |
| **Custom Rule-based**| Handle complex situations, like URLs with long parameters, dynamic tokens, or timestamps. | Manually select the key part to filter (e.g., `token=xxxx`) in the request, and let the extension intelligently generate the rule. |

### 2. Group Management Feature

To address rule confusion during multi-target testing, FilterPro introduces a group management feature.

![image-20260124145852380](https://github.com/Flinvvan/FilterPro/blob/main/images/2.png)

- You can create independent rule groups for **different test sites or projects**.
- All rules are saved in **a single configuration file**, making it easy to carry and share.
- During testing, simply **switch the active group** to apply the corresponding rule set, achieving "one-click filtering" for different targets.

### 3. How to Use the Filtering Rules

Using the rules is a simple three-step process to achieve precise noise reduction:

1.  **Generate Rules**: Check the desired filtering rules or create new ones in the extension interface, then click the **「Generate Regex」** button.

    ![image-20260124150007531](https://github.com/Flinvvan/FilterPro/blob/main/images/3.png)

2.  **Paste into Burp Filter**: Navigate to the **Proxy -> HTTP history** tab in Burp, find the filter input box, and paste the regular expression from the clipboard.

    ![image-20260124150233777](https://github.com/Flinvvan/FilterPro/blob/main/images/4.png)

3.  **Enable Regex Matching**: Don't forget to enable these two crucial settings for the filter to work.

    ![image-20260124150200844](https://github.com/Flinvvan/FilterPro/blob/main/images/5.png)

## ❤️ Supporting the Project

If FilterPro has effectively improved your testing efficiency, you are welcome to show your appreciation in the following ways.

- ⭐**Give a Star**: This is the greatest encouragement for the developer!!!
- 📝**Provide Feedback**: Submit an Issue or join discussions to help improve the extension.
- 📢**Share with Others**: If your peers are also troubled by noise packets, feel free to recommend this tool to them.

---

<div align="center" style="font-size: 15px; font-weight: 700;">
  精准过滤，高效聚焦 | Precise Filtering, Efficient Focus.
</div>

</div>
