package net.sourceforge.openstego.plugin.f5;

import net.sourceforge.openstego.OpenStegoException;
import net.sourceforge.openstego.plugin.f5.lib.JpegEncoder;
import net.sourceforge.openstego.plugin.template.image.DHImagePluginTemplate;

import javax.imageio.ImageIO;
import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.List;

/**
 * F5 implementation
 *
 * @author Lukasz Piliszczuk <lukasz.pili AT gmail.com>
 */
public class F5Plugin extends DHImagePluginTemplate {

    /**
     * default password for the message in jpeg compression but we don't care as the message is already encrypted upstream by AES or DES
     */
    private static final String PASSWORD = "abcd1234";
    private static final String COMMENT = "JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech.";

    @Override
    public String getName() {
        return "F5";
    }

    @Override
    public String getDescription() {
        return "F5 algorithm";
    }

    @Override
    public byte[] embedData(byte[] msg, String msgFileName, byte[] cover, String coverFileName, String stegoFileName) throws OpenStegoException {

        Image coverImage;
        try {
            coverImage = ImageIO.read(new ByteArrayInputStream(cover));
        } catch (IOException e) {
            throw new OpenStegoException(e);
        }

        // be sure to trim before
        msgFileName = msgFileName.trim();

        // create the byte array for the filename and fill the remaining space with ' ' bytes
        byte[] filenameBytes = msgFileName.getBytes();
        byte[] finalFilenameBytes = new byte[50];
        for (int i = 0; i < 50; i++) {
            if (i < filenameBytes.length) {
                finalFilenameBytes[i] = filenameBytes[i];
            } else {
                finalFilenameBytes[i] = ' ';
            }
        }

        // merge filename and file byte arrays
        byte[] in = new byte[msg.length + finalFilenameBytes.length];
        System.arraycopy(finalFilenameBytes, 0, in, 0, finalFilenameBytes.length);
        System.arraycopy(msg, 0, in, finalFilenameBytes.length, msg.length);

        InputStream messageInputStream = new ByteArrayInputStream(in);

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        JpegEncoder jpegEncoder = new JpegEncoder(coverImage, 80, out, COMMENT);
        jpegEncoder.Compress(messageInputStream, PASSWORD);

        return out.toByteArray();
    }

    @Override
    public String extractMsgFileName(byte[] stegoData, String stegoFileName) throws OpenStegoException {
        InputStream is = new ByteArrayInputStream(stegoData);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        try {
            new F5Extract().extract(is, stegoData.length, os, PASSWORD);
        } catch (final Exception e) {
            throw new OpenStegoException(e);
        }

        return new String(os.toByteArray(), 0, 49).trim();
    }

    @Override
    public byte[] extractData(byte[] stegoData, String stegoFileName, byte[] origSigData) throws OpenStegoException {

        InputStream is = new ByteArrayInputStream(stegoData);
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        try {
            new F5Extract().extract(is, stegoData.length, os, PASSWORD);
        } catch (final Exception e) {
            throw new OpenStegoException(e);
        }

        return Arrays.copyOfRange(os.toByteArray(), 50, os.toByteArray().length);
    }

    @Override
    public String getUsage() throws OpenStegoException {
        return "F5 plugin";
    }

    @Override
    public List getReadableFileExtensions() throws OpenStegoException {
        return Arrays.asList("jpg");
    }

    @Override
    public List getWritableFileExtensions() throws OpenStegoException {
        return Arrays.asList("jpg");
    }
}
