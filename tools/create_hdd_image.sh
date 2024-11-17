echo "Creating virtual disk image..."

rm -rf build/hdd.img
# 创建一至少为16MB磁盘镜像（类型选择raw）
qemu-img create -f raw build/hdd.img 16M

# 使用fdisk把build/hdd.img的分区表设置为MBR格式(下方的空行请勿删除)
fdisk build/hdd.img <<EOF
o
n




w
EOF

LOOP_DEVICE=$(sudo losetup -f --show -P build/hdd.img) ||
    exit 1
echo ${LOOP_DEVICE}p1
sudo mkfs.vfat -F 32 ${LOOP_DEVICE}p1
sudo losetup -d ${LOOP_DEVICE}

echo "Successfully created disk image."
