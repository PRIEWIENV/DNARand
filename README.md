# 实验

## 实验目的

测试此随机数生成协议在不同节点数量及配置的情况下的生成速度

## 实验假设

* 节点间网络及连接状态良好，建立好的 TCP Socket 在程序结束以前始终保持连接
* 无恶意节点，所有节点均尽力按照协议流程运行

## 实验环境

主要使用阿里云同一区域(华北一)的共享型虚拟机进行实验

## 实验方法

1. 将代码放到一台开好的机器上，将其编译。
2. 从步骤1 中的机器创建镜像
3. 从镜像创建一定数量的虚拟机
4. 每个节点使用 `config_gen.py` 生成符合要求的配置文件
5. 运行约30秒，根据迭代次数和总耗时计算得到迭代速度
6. 多次运行取平均值

## 实验说明

1. 节点间并不一定需要互相路由可达，即每个节点还需要承担转发消息的工作
2. 对于广播的实现方式是洪泛
3. 由于一些原因，代码实现中对于每一对 Socket 使用了一个线程来进行维护，导致上下文切换带来的Overhead 过大，之后的代码中会更改这部分的实现方法
4. 实验中的连接状况是指 `对于一个节点，它对其他多少节点发起建立了 TCP Socket`, 例如 1/2连接 是指每一个节点对所有节点的其中随机1/2发起建立了连接, 全连接则是指每一个节点都对其他所有节点发起建立了连接
5. 连接建立越多则消息传播延迟会更小，但本实现中带来的上下文切换开销会更大

## 实验结果

|节点数量|节点配置|网络情况|连接情况|迭代速度|
|-------|-------|-------|-------|-----|
|3|i7-7700HQ 4 cores|localhost|全连接|300轮/s|
|4|E5-2682v4 1 core|阿里云同区域|全连接|140轮/s|
|4|E5-2682v4 4 cores|阿里云同区域|全连接|225轮/s|
|6|E5-2682v4 4 cores|阿里云同区域|全连接|100轮/s|
|6|E5-2682v4 4 cores|阿里云同区域|1/2连接|140轮/s|
|6|E5-2682v4 4 cores|阿里云同区域|1/3连接|120轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|全连接|36轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|1/2连接|72轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|1/3连接|80轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|1/4连接|85轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|1/5连接|112轮/s|
|8|E5-2682v4 4 cores|阿里云同区域|1/6连接|80轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|全连接|7轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|1/2连接|23轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|1/3连接|25轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|1/4连接|40轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|1/5连接|55轮/s|
|12|E5-2682v4 4 cores|阿里云同区域|1/6连接|60轮/s|
|12|8163 12 cores|阿里云同区域|全连接|14轮/s|
|12|8163 12 cores|阿里云同区域|1/2连接|20轮/s|
|12|8163 12 cores|阿里云同区域|1/3连接|30轮/s|
|12|8163 12 cores|阿里云同区域|1/4连接|45轮/s|
|28|8163 12 cores|阿里云同区域|1/4连接|12轮/s|
|28|8163 12 cores|阿里云同区域|1/6连接|20轮/s|
|28|8163 12 cores|阿里云同区域|1/10连接|28轮/s|
|28|8163 12 cores|阿里云同区域|1/14连接|36轮/s|

## 优化后的实验结果

|节点数量|节点配置|网络情况|连接情况|迭代速度|
|-------|-------|-------|-------|-----|
|3|i9-8950HK 6 cores|localhost|全连接|854轮/s|
|4|8163 12 cores|阿里云同区域|全连接|454轮/s|
|4|8163 12 cores|阿里云同区域|全连接|625轮/s|
|6|8163 12 cores|阿里云同区域|全连接|201轮/s|
|6|8163 12 cores|阿里云同区域|1/2连接|303/s|
|6|8163 12 cores|阿里云同区域|1/3连接|370轮/s|
|8|8163 12 cores|阿里云同区域|全连接|102轮/s|
|8|8163 12 cores|阿里云同区域|1/2连接|166轮/s|
|8|8163 12 cores|阿里云同区域|1/3连接|222轮/s|
|8|8163 12 cores|阿里云同区域|1/4连接|303轮/s|
|12|8163 12 cores|阿里云同区域|全连接|50轮/s|
|12|8163 12 cores|阿里云同区域|1/2连接|62轮/s|
|12|8163 12 cores|阿里云同区域|1/3连接|80轮/s|
|12|8163 12 cores|阿里云同区域|1/4连接|110轮/s|
|12|8163 12 cores|阿里云同区域|1/6连接|140轮/s|
|28|8163 12 cores|阿里云同区域|1/4连接|20轮/s|
|28|8163 12 cores|阿里云同区域|1/6连接|31轮/s|
|28|8163 12 cores|阿里云同区域|1/10连接|40轮/s|
|28|8163 12 cores|阿里云同区域|1/14连接|49轮/s|
