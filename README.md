# BMW-IVI-NBT-ingest-module Autopsy

## Analysis of in-vehicle infotainment systems of BMW brand vehicles, in the 2017 series 5 and 7 models, with IVI NBT systems

As the Autopsy tool does not support the QNX file system, it was necessary to manually mount the partitions using a Linux distribution and then manually load these partitions into Autopsy to perform the analysis.
Version 4.18.0 of the Autopsy tool was used.

## Mount the Partitions

### To mount the partitions we use Kali linux

 - We run the following commands:

### sudo fdisk -lu test.dd 

![image](https://user-images.githubusercontent.com/33206506/190868972-3047054a-206b-47d1-82b7-d76a29ba0b8c.png)


### sudo losetup --partscan --find --show test.dd

### sudo ls -la /dev/loop0*

![image](https://user-images.githubusercontent.com/33206506/190868995-1cc588c2-e9d1-4ff1-8ec6-b8e1904a9e45.png)

### sudo mount -t qnx6  /dev/loop3p1 /dev/disk

### sudo mount -t qnx6  /dev/loop3p2 /dev/disk

### sudo mount -t qnx6  /dev/loop3p3 /dev/disk

### sudo mount -t qnx6  /dev/loop3p4 /dev/disk

![image](https://user-images.githubusercontent.com/33206506/190869029-34c43cbe-c767-4881-8112-f5bfdd393c91.png)



# Autopsy

 - To load the partitions to the Autopsy tool, we first have to select what type of data we are going to select, in this case we choose Logical Files, to add the folders that correspond to each partition.

![image](https://user-images.githubusercontent.com/33206506/190868642-2adc99d3-b3fd-4f1a-b910-8baeb4ba4afc.png)


![image](https://user-images.githubusercontent.com/33206506/190869067-c93d80fa-56b8-4ded-9195-b76128d974d9.png)


![image](https://user-images.githubusercontent.com/33206506/190869079-771403ae-8cc4-4ed7-8474-66bbcff2f72c.png)


![image](https://user-images.githubusercontent.com/33206506/190869102-ccfe71e7-44dc-4be4-a463-8be1fdea2335.png)


![image](https://user-images.githubusercontent.com/33206506/190869112-366eb2aa-2662-46de-a1de-4c4d76164546.png)


![image](https://user-images.githubusercontent.com/33206506/190869115-1e91bab0-1842-42fd-9eb3-0e441cfbbf11.png)


