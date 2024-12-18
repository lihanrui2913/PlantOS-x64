# ======检查是否以sudo运行=================
uid=`id -u`
if [ ! $uid == "0" ];then
 echo "请以sudo权限运行"
 exit
fi

LOOP_DEVICE=$(losetup -f --show -P build/hdd.img) \
    || exit 1

echo ${LOOP_DEVICE}p1

mkdir -p mnt_point
mount ${LOOP_DEVICE}p1 mnt_point

mkdir mnt_point/dev/
touch mnt_point/dev/kbd.dev

mkdir -p mnt_point/efi/boot/
cp assets/limine/bootx64.efi mnt_point/efi/boot/
cp assets/limine/limine-bios.sys mnt_point/
cp assets/limine/limine.conf mnt_point/
