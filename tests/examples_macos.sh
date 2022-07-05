#! /bin/zsh

# Note that we don't test all files, because some are not well parsed by the
# system's otool.

for file in tests/binary_input/macho/{[DLST],lib[AScde],macho_}*; do
echo "=== $file ==="
diff -c =(otool -l $file) =(python ./examples/otool.py --llvm=native -l $file 2>/dev/null)
done
