<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="rc5.css">
</head>

<body>
    <h1>RC5 Şifreleme Algoritması</h1>
    <form method="post" action="rc5.php" enctype="multipart/form-data">
        <label for="key">Anahtar Değeri:</label>
        <input type="text" id="key" name="key" required><br><br>
        <label for="file">Dosya Seçin:</label>
        <input type="file" id="file" name="file" required><br><br>
        <input type="submit" value="Şifrele">
    </form>
</body>
</html>

<?php

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $key = $_POST["key"];
    $file = $_FILES["file"];

    // Dosyanın geçici dosya yolunu al
    $tmpName = $file["tmp_name"];

    // Şifrelenecek dosyanın yeni adını oluştur
    $encryptedFileName = "encrypted.txt";

    // Dosyayı oku
    $input = file_get_contents($tmpName);

    // RC5 Şifreleme Algoritmasını kullanarak dosyayı şifrele
    $w = 32; // kelime boyutu (32 bit)
    $r = 12; // yineleme sayısı
    $key = str_pad($key, 16, "\x00"); // anahtarın uzunluğunu 16 byte yap

    $S = array();
    for ($i = 0; $i < 2 * $r + 2; $i++) {
        $S[$i] = $i;
    }

    $L = array_values(unpack("V2", $key));
    $T = array();
    $T[0] = 0xB7E15163;

    for ($i = 1; $i <= 2 * $r + 3; $i++) {
        $T[$i] = ($T[$i - 1] + 0x9E3779B9) & 0xFFFFFFFF;
    }

    $A = 0;
    $B = 0;

    $inFile = fopen($tmpName, "rb");
    $outFile = fopen($encryptedFileName, "wb");
    while (!feof($inFile)) {
        $input = fread($inFile, 8);
        if (strlen($input) == 8) {
            $A = (unpack("V", $input))[1];
            $B = (unpack("V", substr($input, 4)))[1];
        }


        $A = ($A + $S[0]) & 0xFFFFFFFF;
        $B = ($B + $S[1]) & 0xFFFFFFFF;

        for ($i = 1; $i <= $r; $i++) {
            $A = (($A ^ $B) << ($B & 31)) | (($A ^ $B) >> ($w - ($B & 31)));
            $A = ($A + $T[2 * $i]) & 0xFFFFFFFF;
            $B = (($B ^ $A) << ($A & 31)) | (($B ^ $A) >> ($w - ($A & 31)));
        }

        $A = ($A + $S[2]) & 0xFFFFFFFF;
        $B = ($B + $S[3]) & 0xFFFFFFFF;

        $output = pack("V2", $A, $B);
        fwrite($outFile, $output);
    }

    fclose($inFile);
    fclose($outFile);

    echo "Dosya başarıyla şifrelendi ve kaydedildi: " . $encryptedFileName;

    // Şifreli dosyayı çöz
    $decryptedFileName = "decrypted.txt";

    $inFile = fopen($encryptedFileName, "rb");
    $outFile = fopen($decryptedFileName, "wb");

    while (!feof($inFile)) {
        $input = fread($inFile, 8);
        if (strlen($input) == 8) {
            $A = (unpack("V", $input))[1];
            $B = (unpack("V", substr($input, 4)))[1];
        }

        $B = (($B << ($w - ($A & 31)))) ^ $A;
        $B = ($B - $T[2 * $r + 3]) & 0xFFFFFFFF;
        $A = (($A << ($w - ($B & 31)))) ^ $B;
        $A = ($A - $T[2 * $r + 2]) & 0xFFFFFFFF;

        for ($i = $r; $i >= 1; $i--) {
            $B = (($B >> ($A & 31)) | ($B << ($w - ($A & 31)))) ^ $A;
            $B = ($B - $T[2 * $i + 1]) & 0xFFFFFFFF;
            $A = (($A >> ($B & 31)) | ($A << ($w - ($B & 31)))) ^ $B;
            $A = ($A - $T[2 * $i]) & 0xFFFFFFFF;
        }

        $A = ($A - $S[0]) & 0xFFFFFFFF;
        $B = ($B - $S[1]) & 0xFFFFFFFF;

        $output = pack("V2", $A, $B);
        $keyBytes = strlen($key);
        fwrite($outFile, file_get_contents($tmpName), $keyBytes);
    }

    fclose($inFile);
    fclose($outFile);

    echo "Dosya başarıyla çözüldü ve kaydedildi: " . $decryptedFileName;

    echo "\t\n\n\n\tDosyalar bulunduğunuz dizine kaydedilmiştir.";
}
?>