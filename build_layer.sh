version=${1}

find ./ -name __pycache__ |xargs -I {} rm -rf {}

rm -rf layer_build || echo ""
mkdir layer_build
cd layer_build
pip3 --python /opt/homebrew/bin/python3.12 install \
    --no-cache \
    --platform manylinux2014_x86_64 --implementation cp  \
    --only-binary=:all: \
    --upgrade \
    --target python \
     ..

rm -rf python/registry* python/terraform_lambda_module_registry*

find ./ -name __pycache__ |xargs -I {} rm -rf {}

zip -r ../layer.zip .

cd ..
rm -rf layer_build

aws lambda publish-layer-version \
    --zip-file fileb://layer.zip \
    --layer-name terraform-registry-deps \
    --compatible-runtimes python3.12

rm -rf lambda_layer.zip
