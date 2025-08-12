# Project 6:  Google Password Checkup验证

本项目参考论文 https://eprint.iacr.org/2019/723.pdf 的 section 3.1 ，也即 Figure 2 中展示的协议，并且尝试实现该协议，做到了在两个参与方之间，在不泄露彼此非交集数据的前提下，安全地计算交集对应值的“求和”。

##  特性 Features

-  功能 1 找出双方集合交集中的元素
-  功能 2 私密地加和这些元素对应的权重值（由另一方持有）
-  功能 3 在这个过程中，双方不知道对方的信息，P1方不知道P2所持有的权重，P2不知道P1持有的集合信息

##  安装 Installation

```bash
git clone https://github.com/SDU-cyberspace-wz/Lab-project.git
cd Lab-project/Project6
```
##  运行 Running
main文件中存在demo，直接运行main即可。