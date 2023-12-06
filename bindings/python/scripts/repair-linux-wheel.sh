# Repair the linux wheel created by cibuildwheel
wheel=$1
dest_dir=$2
rename 's/(.*)-py3-none-.*.whl/$1-py3-none-any.whl/s' $wheel
root=$(dirname $wheel)
ls $root"
auditwheel repair -w $dest_dir $root/*.whl
