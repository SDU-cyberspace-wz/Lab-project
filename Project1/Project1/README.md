# Project 1:  SM4的软件实现和优化

本项目用C++来做 sm4加密的 基础实现，包括加密功能和GCM模式下的加密签名功能，并对SM4进行性能优化。
##  优化方案 

###  T_table优化
由于SM4需要进行S盒查找和线性变换，因此我使用T_table，通过查表来原来的方法进行优化。

### AES-NI
AES-NI指令集是为了优化AES加密算法而出现的，但同样适用于对SM4加密算法的优化，我们可以优化其S盒查找和线性变换的执行效率。


### GCM优化
GCM模式是一个 基于计数器模式（CTR） 的分组加密认证模式，核心由两部分组成：

- 加密部分（CTR模式）：用于加密明文。

- 认证部分（GHASH）：用于计算认证标签（MAC）。

因此，在CTR模式中，我使用T_table对加密进行优化，而在认证部分，我同样通过查表的方法，优化GHASH的执行效率。
##  安装 Installation

```bash
git clone https://github.com/Sunburnlyz/MyProject.git
cd MyProject/Project1
```
##  运行 Running
程序中给出了三种优化方法的测试用例，可以直接运行main函数进行验证。
