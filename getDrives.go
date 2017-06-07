package main

//Test the getDrives function

import (
    "errors"
    "fmt"
    "strings"
    "syscall"
    "unsafe"
)

func main() {
    drives, err := getDrives()
    if err != nil {
        panic(err)
    }
    for _, drive := range drives {
        fmt.Println(drive)
    }
}

func getDrives() ([]string, error) {
    //Returns string of physical and removable drives (excludes network and cd-rom drives)

    var drives []string
    var err error

    //Get logical drive names
    kernel32, err := syscall.LoadDLL("kernel32.dll")
    getLogicalDriveStringsHandle, err := kernel32.FindProc("GetLogicalDriveStringsA")
    if err != nil {
        return drives, err
    }

    //create buffer
    buffer := [1024]byte{}
    bufferSize := uint32(len(buffer))
    ret1, _, err := getLogicalDriveStringsHandle.Call(uintptr(unsafe.Pointer(&bufferSize)), uintptr(unsafe.Pointer(&buffer)))
    if ret1 == 0 {
        return drives, err
    }

    //0 value means no drives were found
    if ret1 == 0 {
        err = errors.New("No drives returned from GetLogicalDriveStringsA")
        return drives, err
    } else {

        //format drives name into slice of strings
        s := strings.Trim(string(buffer[:ret1]), "\x00")
        var lines []string
        lines = strings.Split(s, "\x00")

        //get the drive type for each drive
        for _, l := range lines {
            getDriveTypeHandle, _ := kernel32.FindProc("GetDriveTypeW")
            ret1, _, _ := getDriveTypeHandle.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(l))))

            //store drive types 2 and 3 (physical and removable)
            if ret1 == 2 || ret1 == 3 {
                drives = append(drives, l)
            }
        }
    }
    return drives, nil
}
