# Project 5:  SM2的软件实现优化

本项目基于 Python 实现 SM2 算法的基础功能，包括加密解密、签名与验签及密钥协商功能，并针对签名算法验证场景完成 PoC 验证，同时提供完整的推导文档。
##  特性 Features

-  进行了SM2的加解密、签名验签和密钥协商，并给出demo
-  对四种密钥误用都给出了推导文档
-  四种密钥误用都有验证代码，可以证明存在误用情况下，可以推导出原本的私钥

##  安装 Installation

```bash
git clone https://github.com/SDU-cyberspace-wz/Lab-project.git
cd Lab-project/Project5
```
##  运行 Running
项目包含三个核心文件，分别对应以下功能：

- SM2 加解密与签名验签
- 密钥协商
- 密钥误用 PoC 验证

每个文件均包含独立的演示示例（demo），可单独运行进行功能验证。