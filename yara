rule apt_reaper {
    meta:
        identification = "2e4c7384-17b8-4d95-b4a3-3c3a82e8a862"
        version = "1.0"
        intrusion_set = "Segador"
        source = "SEKOIA.IO"
        created = "2023-03-18"
        classification = "TLP: BLANCO"
        Author: "Fevar54"
    strings:
        $reaper1 = "Segador"
        $reaper2 = /C7 [84|85] [\x24|\x85] [\x00-\xff]{2} [\x00-\xff]{8} [\x00-\xff]{1}/
        $reaper3 = /33C0 EB [0|3] [\x8D|\x8B] [\x49|\x84|\x9B|\x8C] [\x00-\xff]{2} [\x3B|\x2D] [\x8C|\x85] [\x00-\xff]{3} [\x00-\xff]{3}/
        $reaper4 = /<HTML>/ nocase
        $reaper5 = "UwB0AGEAcgB0AC0AUwBs" ascii
        $reaper6 = "= nuevo ActiveXObject(" ascii
        $reaper7 = "\", \"\", \"abrir\", 0);" ascii
        $reaper8 = ".moverA(" ascii
        $reaper9 = "auto.cerrar();"
        $reaper10 = "$env:NOMBRE DE COMPUTADORA + '-' + $env:NOMBRE DE USUARIO;"
        $reaper11 = "mientras ($verdadero -eq $verdadero)"
        $reaper12 = "Inicio-Dormir -Segundos"
        $reaper13 = " -ne 'null' -and $"
        $reaper14 = "= 'R=' + [System.Convert]::"
        $reaper15 = "[cadena]$([char]0x0D) + [cadena]$([char]0x0A);"
        $reaper16 = "establecer tiempo de espera (verificar carga,"
        $reaper17 = "commChannel.addListener("
        $reaper18 = "si no (commType =="
        $reaper19 = "?dir=ABAJO&método=LEER&id="
        $reaper20 = "Contenido: base64_encode (upload_data)"
        $reaper21 = "$.post(upHttpRelayer"
        $reaper22 = "var ablyUpData = {"
    condition:
        uint16be(0) == 0x4d5a and
        filesize < 1MB and
        (
            $reaper1 or
            (
                ($reaper2 and $reaper3) or
                all of ($reaper4, $reaper5, $reaper6, $reaper7, $reaper8, $reaper9)
                or
                all of ($reaper10, $reaper11, $reaper12, $reaper13, $reaper14, $reaper15)
                or
                all of ($reaper16, $reaper17, $reaper18, $reaper19, $reaper20, $reaper21, $reaper22)
            )
        )
}
