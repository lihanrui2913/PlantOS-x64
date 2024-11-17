uid=`id -u`
if [ ! $uid == "0" ];then
 echo "请以sudo权限运行"
 exit
fi

LOOP_DEVICE=$(lsblk | grep mnt_point)
umount -f mnt_point
losetup -d /dev/${LOOP_DEVICE:2:5}
echo ${LOOP_DEVICE:2:5}
rm -rf mnt_point
