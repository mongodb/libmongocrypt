# Repair the linux wheel created by cibuildwheel
wheel=$1
dest_dir=$2
new_name=$(echo "$wheel" | sed -E "s/(.*)-py3-none-.*.whl/\1-py3-none-any.whl/")
mv $wheel $new_name
auditwheel repair -w $dest_dir $new_name
