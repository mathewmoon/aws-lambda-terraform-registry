find ./ -name __pycache__ |xargs -I {} rm -rf {}

rm -rf build || echo ""
pip3 install --no-cache . -t build
cd build
find ./ -name __pycache__ |xargs -I {} rm -rf {}
zip -r ../registry.zip .
cd ..
aws --no-paginate lambda update-function-code --function-name terraform-registry-test --zip-file fileb://./registry.zip --publish
aws --no-paginate lambda update-function-code --function-name terraform-iam-auth --zip-file fileb://./registry.zip --publish
rm -rf build
rm -rf dist
