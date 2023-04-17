# 💾 PEReader.js
You can read the PE Format.

## How to use?
```html
<!-- You need a 'BinaryReader.js' -->
<script src="./BinaryReader.js"></script>
<script src="./PEReader.js"></script>
<script>
    let br = new BinaryReader();
    
    // Read the fihe with FileReader.
    let reader = new FileReader();
    reader.onload = function(e) {
        let binData = e.target.result;
        let dataView = new DataView(binData);
        
        let arr = [];
        for (let i = 0; i < binData.length; i++) {
            arr.push(dataView.getUint8(i));
        }
        
        // Read
        br.ReadData(arr);
        
        // PE        
        let pereader = new PEHeaderReader();
        pereader.Read(br);
</script>
```

[BinaryReader.js](https://github.com/Ssims-kr/BinaryReader.js)

## Example
[Online PE Viewer](https://ssims-kr.github.io/OPV/index.html)
