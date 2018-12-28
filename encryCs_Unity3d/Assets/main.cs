using System.Collections;
using System.Collections.Generic;
using System.IO;
using UnityEngine;
using System.Security.Cryptography;
using System;
using System.Text;

public class main : MonoBehaviour {

    // Use this for initialization
    void Start () {
        RsaEncrypt.init();
        ClientSocket.g_cs.Connect ("10.2.61.130", 8887);
    }


    // Update is called once per frame
    void Update () {
        
    }


}
