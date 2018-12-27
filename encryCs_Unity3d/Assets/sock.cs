using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

public class ClientSocket
{
    public static ClientSocket g_cs = new ClientSocket();

    TcpClient m_client;
    BinaryReader m_sr;
    BinaryWriter m_wr;
    ClientSocket()
    {
        m_sr = null;
        m_wr = null;
    }

    public void Connect(string ip, int port)
    {
        m_client = new TcpClient(ip, port);
        try
        {
            Stream s = m_client.GetStream();
            m_sr = new BinaryReader(s);
            m_wr = new BinaryWriter(s);
            handleRsa();
        }
        finally
        {
            m_client.Close();
        }
    }
	private static System.Random random = new System.Random();
	public static string RandomString(int length)
	{
		const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		string ret = "";
		for (int i = 0; i < length; i++) {
			int rv = random.Next (chars.Length);
			ret += chars [rv];
		}
		return ret;    
	}

    void handleRsa()
    {
		byte[] aesPwd;

        int len = m_sr.ReadInt32();
        byte[] buf = new byte[len];
        m_sr.Read(buf, 0, len);
        Debug.Log("handleRsa recv len:" + len);
		aesPwd = RsaEncrypt.RSADecrypt(buf, RsaEncrypt.GetCPri());

		Debug.Log("recv:" + Encoding.ASCII.GetString(aesPwd));
		byte[] snd = RsaEncrypt.RSAEncrypt(aesPwd, RsaEncrypt.GetSPub());
        m_wr.Write(snd.Length);
        m_wr.Write(snd);
		Debug.Log ("send len:" + snd.Length);

		int cstLen = 10240;
		string[] sndAry = new string[cstLen];
		for (int i = 0; i < cstLen; i++) {
			sndAry[i] = RandomString (i+1);
		}
		double start = (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
		//Aes encrypt
		for (int i = 0; i < cstLen; i++) {
			//send&encry
			string tmpStr = sndAry[i];
			byte[] sndv = AES256.getInst ().Encrypt (tmpStr);
			m_wr.Write (sndv.Length);
			m_wr.Write (sndv);

			//recv&decry
			len = m_sr.ReadInt32();
			byte[] bufv = new byte[len];
			m_sr.Read (bufv, 0, len);
			byte[] recvv = AES256.getInst ().Decrypt (bufv);
			if( Encoding.UTF8.GetString(recvv).Equals(tmpStr) == false){
				Debug.LogError ("not eq; sndv:" + tmpStr + ",recvv:" + Encoding.UTF8.GetString(recvv) );
				break;
			} else {
				double rate = (bufv.Length-tmpStr.Length)/ (1.0f * tmpStr.Length);
				Debug.Log ("aes succ; len:" + tmpStr.Length +",enclen:"+bufv.Length +",rate:"+rate+", tmpStr:" + tmpStr);
			}
		}
		Debug.Log ("use time: "+((DateTime.UtcNow.Subtract (new DateTime (1970, 1, 1))).TotalSeconds - start) );

    }


}

