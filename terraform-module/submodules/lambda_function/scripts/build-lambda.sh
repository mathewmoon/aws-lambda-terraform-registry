package_name=${1}
package_version=${2}
build_dir=${3}

[[ -d "${build_dir}" ]] || mkdir -p "${build_dir}"
cd ${build_dir}

pip3 install --no-cache \
    -t ${build_dir} \
    --no-deps \
    --no-cache \
    "${package_name}==${package_version}" > /dev/null 2>&1

cd build

find ./ -name __pycache__ |xargs -I {} rm -rf {}  > /dev/null 2>&1
zip -r ../${package_name}-${package_version}.zip .  >${build_dir}/log.txt 2>&1
cd ..
path=$(find $(pwd) -name "${package_name}-${package_version}.zip")

echo "{\"zip_file\": \"${path}\"}"