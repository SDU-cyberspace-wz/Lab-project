# Project 5:  SM2的软件实现优化

本项目用python来做 sm2的 基础实现，包括加密解密、签名与验签和密钥协商功能，并对其中各种签名算法的验证做poc验证，并且给出推导文档。
##  特性 Features

-  进行了SM2的加解密、签名验签和密钥协商，并给出demo
-  对四种密钥误用都给出了推导文档
-  四种密钥误用都有验证代码，可以证明存在误用情况下，可以推导出原本的私钥

##  安装 Installation

```bash
git clone https://github.com/Sunburnlyz/MyProject.git
cd MyProject/pythonProject5
```
##  运行 Running
三个文件分别对应SM2加解密与签名验签、密钥协商和密钥误用Poc验证，三个文件各自存在demo，可以单独运行。