/*
 * Steganography utility to hide messages into cover files
 * Author: Samir Vaidya (mailto:syvaidya@gmail.com)
 * Copyright (c) 2007-2008 Samir Vaidya
 */

package net.sourceforge.openstego.plugin.dwtxie;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Random;

import net.sourceforge.openstego.OpenStegoException;
import net.sourceforge.openstego.plugin.template.image.WMImagePluginTemplate;
import net.sourceforge.openstego.util.ImageUtil;
import net.sourceforge.openstego.util.LabelUtil;
import net.sourceforge.openstego.util.StringUtil;
import net.sourceforge.openstego.util.dwt.DWT;
import net.sourceforge.openstego.util.dwt.DWTUtil;
import net.sourceforge.openstego.util.dwt.ImageTree;

/**
 * Plugin for OpenStego which implements the DWT based algorithm by Xie.
 * 
 * This class is based on the code provided by Peter Meerwald at:
 * http://www.cosy.sbg.ac.at/~pmeerw/Watermarking/
 * 
 * Refer to his thesis on watermarking: Peter Meerwald, Digital Image Watermarking in the Wavelet Transfer Domain,
 * Master's Thesis, Department of Scientific Computing, University of Salzburg, Austria, January 2001.
 */
public class DWTXiePlugin extends WMImagePluginTemplate
{
    /**
     * LabelUtil instance to retrieve labels
     */
    private static LabelUtil labelUtil = LabelUtil.getInstance(DWTXiePlugin.NAMESPACE);

    /**
     * Constant for Namespace to use for this plugin
     */
    public final static String NAMESPACE = "DWTXIE";

    /**
     * Default constructor
     */
    public DWTXiePlugin()
    {
        LabelUtil.addNamespace(NAMESPACE, "net.sourceforge.openstego.resource.DWTXiePluginLabels");
        new DWTXieErrors(); // Initialize error codes
    }

    /**
     * Gives the name of the plugin
     * @return Name of the plugin
     */
    public String getName()
    {
        return "DWTXie";
    }

    /**
     * Gives a short description of the plugin
     * @return Short description of the plugin
     */
    public String getDescription()
    {
        return labelUtil.getString("plugin.description");
    }

    /**
     * Method to embed the message into the cover data
     * @param msg Message to be embedded
     * @param msgFileName Name of the message file. If this value is provided, then the filename should be embedded in
     *            the cover data
     * @param cover Cover data into which message needs to be embedded
     * @param coverFileName Name of the cover file
     * @param stegoFileName Name of the output stego file
     * @return Stego data containing the message
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public byte[] embedData(byte[] msg, String msgFileName, byte[] cover, String coverFileName, String stegoFileName)
            throws OpenStegoException
    {
        BufferedImage image = null;
        ArrayList yuv = null;
        DWT dwt = null;
        ImageTree dwtTree = null;
        ImageTree p = null;
        Signature sig = null;
        Pixel pixel1 = null;
        Pixel pixel2 = null;
        Pixel pixel3 = null;
        int[][] luminance = null;
        int origWidth = 0;
        int origHeight = 0;
        int cols = 0;
        int rows = 0;
        int n = 0;
        double temp = 0.0;

        // Cover file is mandatory
        if(cover == null)
        {
            throw new OpenStegoException(NAMESPACE, DWTXieErrors.ERR_NO_COVER_FILE, null);
        }
        else
        {
            image = ImageUtil.byteArrayToImage(cover, coverFileName);
        }

        origWidth = image.getWidth();
        origHeight = image.getHeight();
        image = ImageUtil.makeImageSquare(image);

        cols = image.getWidth();
        rows = image.getHeight();
        yuv = ImageUtil.getYuvFromImage(image);
        luminance = (int[][]) yuv.get(0);
        sig = new Signature(msg);

        // Wavelet transform
        dwt = new DWT(cols, rows, sig.filterID, sig.embeddingLevel, sig.waveletFilterMethod);
        dwtTree = dwt.forwardDWT(luminance);

        p = dwtTree;
        // Consider each resolution level
        while(p.getLevel() < sig.embeddingLevel)
        {
            // Descend one level
            p = p.getCoarse();
        }

        // Repeat binary watermark by sliding a 3-pixel window of approximation image
        for(int row = 0; row < p.getImage().getHeight(); row++)
        {
            for(int col = 0; col < p.getImage().getWidth() - 3; col += 3)
            {
                // Get all three approximation pixels in window
                pixel1 = new Pixel(0, DWTUtil.getPixel(p.getImage(), col + 0, row));
                pixel2 = new Pixel(1, DWTUtil.getPixel(p.getImage(), col + 1, row));
                pixel3 = new Pixel(2, DWTUtil.getPixel(p.getImage(), col + 2, row));

                // Bring selected pixels in ascending order
                if(pixel1.value > pixel2.value)
                {
                    temp = pixel1.value;
                    pixel1.value = pixel2.value;
                    pixel2.value = temp;
                }
                if(pixel2.value > pixel3.value)
                {
                    temp = pixel2.value;
                    pixel2.value = pixel3.value;
                    pixel3.value = temp;
                }
                if(pixel1.value > pixel2.value)
                {
                    temp = pixel1.value;
                    pixel1.value = pixel2.value;
                    pixel2.value = temp;
                }

                // Apply watermarking transformation (modify median pixel)
                temp = wmTransform(sig.embeddingStrength, pixel1.value, pixel2.value, pixel3.value, getWatermarkBit(
                    sig.watermark, n % (sig.watermarkLength * 8)));

                // Write modified pixel
                DWTUtil.setPixel(p.getImage(), col + pixel2.pos, row, temp);

                n++;
            }
        }

        dwt.inverseDWT(dwtTree, luminance);
        yuv.set(0, luminance);
        image = ImageUtil.cropImage(ImageUtil.getImageFromYuv(yuv), origWidth, origHeight);

        return ImageUtil.imageToByteArray(image, stegoFileName, this);
    }

    /**
     * Method to extract the message from the stego data
     * @param stegoData Stego data containing the message
     * @param stegoFileName Name of the stego file
     * @param origSigData Optional signature data file for watermark
     * @return Extracted message
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public byte[] extractData(byte[] stegoData, String stegoFileName, byte[] origSigData) throws OpenStegoException
    {
        ArrayList sigBitList = new ArrayList();
        BufferedImage image = null;
        DWT dwt = null;
        ImageTree dwtTree = null;
        ImageTree p = null;
        Signature sig = null;
        Pixel pixel1 = null;
        Pixel pixel2 = null;
        Pixel pixel3 = null;
        int[][] luminance = null;
        int cols = 0;
        int rows = 0;
        int n = 0;
        double temp = 0.0;

        image = ImageUtil.makeImageSquare(ImageUtil.byteArrayToImage(stegoData, stegoFileName));

        cols = image.getWidth();
        rows = image.getHeight();
        luminance = (int[][]) ImageUtil.getYuvFromImage(image).get(0);
        sig = new Signature(origSigData);

        // Wavelet transform
        dwt = new DWT(cols, rows, sig.filterID, sig.embeddingLevel, sig.waveletFilterMethod);
        dwtTree = dwt.forwardDWT(luminance);

        p = dwtTree;
        // Consider each resolution level
        while(p.getLevel() < sig.embeddingLevel)
        {
            // Descend one level
            p = p.getCoarse();
        }

        // Repeat binary watermark by sliding a 3-pixel window of approximation image
        for(int row = 0; row < p.getImage().getHeight(); row++)
        {
            for(int col = 0; col < p.getImage().getWidth() - 3; col += 3)
            {
                // Get all three approximation pixels in window
                pixel1 = new Pixel(0, DWTUtil.getPixel(p.getImage(), col + 0, row));
                pixel2 = new Pixel(1, DWTUtil.getPixel(p.getImage(), col + 1, row));
                pixel3 = new Pixel(2, DWTUtil.getPixel(p.getImage(), col + 2, row));

                // Bring selected pixels in ascending order
                if(pixel1.value > pixel2.value)
                {
                    temp = pixel1.value;
                    pixel1.value = pixel2.value;
                    pixel2.value = temp;
                }
                if(pixel2.value > pixel3.value)
                {
                    temp = pixel2.value;
                    pixel2.value = pixel3.value;
                    pixel3.value = temp;
                }
                if(pixel1.value > pixel2.value)
                {
                    temp = pixel1.value;
                    pixel1.value = pixel2.value;
                    pixel2.value = temp;
                }

                // Apply inverse watermarking transformation to get the bit value
                sigBitList.add(new Integer(invWmTransform(sig.embeddingStrength, pixel1.value, pixel2.value,
                    pixel3.value)));
                n++;
            }
        }
        sig.setWatermark(convertBitListToByteArray(sigBitList));

        return sig.getSigData();
    }

    /**
     * Method to generate the signature data
     * @return Signature data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public byte[] generateSignature() throws OpenStegoException
    {
        Random rand = null;
        Signature sig = null;

        rand = new Random(StringUtil.passwordHash(config.getPassword()));
        sig = new Signature(rand);

        return sig.getSigData();
    }

    /**
     * Method to check the correlation between original signature and the extracted watermark
     * @param origSigData Original signature data
     * @param watermarkData Extracted watermark data
     * @return Correlation
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public double getWatermarkCorrelation(byte[] origSigData, byte[] watermarkData) throws OpenStegoException
    {
        int corr = 0;
        Signature orig = new Signature(origSigData);
        Signature wm = new Signature(watermarkData);

        for(int i = 0; i < (wm.watermarkLength * 8); i++)
        {
            if(getWatermarkBit(orig.watermark, i % (orig.watermarkLength * 8)) == getWatermarkBit(wm.watermark, i))
            {
                corr++;
            }
            else
            {
                corr--;
            }
        }

        return 0.5 + ((double) corr / (double) (wm.watermarkLength * 8)) / 2;
    }

    /**
     * Method to get the usage details of the plugin
     * @return Usage details of the plugin
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public String getUsage() throws OpenStegoException
    {
        return labelUtil.getString("plugin.usage");
    }

    /**
     * Watermarking transformation, set median pixel to quantization boundary
     */
    private double wmTransform(double alpha, double f1, double f2, double f3, int x)
    {
        double s = alpha * Math.abs(f3 - f1) / 2.0;
        double l = (x != 0) ? (f1 + s) : f1;

        while((l + 2 * s) < f2)
        {
            l += 2 * s;
        }

        return ((f2 - l) < (l + 2 * s - f2)) ? l : (l + 2 * s);
    }

    /**
     * Inverse watermarking transformation, extract embedded bit, check quantization boundaries
     */
    private int invWmTransform(double alpha, double f1, double f2, double f3)
    {
        double s = alpha * Math.abs(f3 - f1) / 2.0;
        double l = f1;
        int x = 0;

        while(l < f2)
        {
            l += s;
            x++;
        }

        if(Math.abs(l - s - f2) < Math.abs(l - f2))
        {
            return (x + 1) % 2;
        }
        else
        {
            return x % 2;
        }
    }

    /**
     * Method to get a bit value from the watermark
     * @param watermark Watermark data
     * @param n Bit number
     * @return Bit value
     */
    private int getWatermarkBit(byte[] watermark, int n)
    {
        int byteNum = n >> 3;
        int bit = n & 7;

        return (watermark[byteNum] & (1 << bit)) >> bit;
    }

    /**
     * Method to set a bit value in the watermark
     * @param watermark Watermark data
     * @param n Bit number
     * @param v Bit value
     */
    private void setWatermarkBit(byte[] watermark, int n, int v)
    {
        int byteNum = n >> 3;
        int bit = n & 7;

        if(v == 1)
        {
            watermark[byteNum] |= (1 << bit);
        }
        else
        {
            watermark[byteNum] &= ~(1 << bit);
        }
    }

    /**
     * Method to convert list of bits into byte array
     * @param bitList List of bits
     * @return Byte array
     */
    private byte[] convertBitListToByteArray(ArrayList bitList)
    {
        byte[] data = null;

        data = new byte[bitList.size() >> 3];
        for(int i = 0; i < ((bitList.size() >> 3) << 3); i++)
        {
            setWatermarkBit(data, i, ((Integer) bitList.get(i)).intValue());
        }

        return data;
    }

    /**
     * Private class for the data structure required for the signature
     */
    private class Signature
    {
        /**
         * Signature stamp
         */
        byte[] sig = "XESG".getBytes();

        /**
         * Length of the watermark (in bytes)
         */
        int watermarkLength = 512;

        /**
         * Embedding strength
         */
        double embeddingStrength = 0.05;

        /**
         * Wavelet filter method
         */
        int waveletFilterMethod = 2;

        /**
         * Filter number
         */
        int filterID = 2;

        /**
         * Embedding level
         */
        int embeddingLevel = 5;

        /**
         * Watermark data
         */
        byte[] watermark = null;

        /**
         * Constructor which generates the watermark data using the given randomizer
         * @param rand Randomizer to use for generating watermark data
         */
        public Signature(Random rand)
        {
            watermark = new byte[watermarkLength];
            rand.nextBytes(watermark);
        }

        /**
         * Constructor that takes existing the signature data
         * @param sigData Existing signature data
         * @throws net.sourceforge.openstego.OpenStegoException
         */
        public Signature(byte[] sigData) throws OpenStegoException
        {
            ObjectInputStream ois = null;
            byte[] inputSig = new byte[sig.length];

            try
            {
                ois = new ObjectInputStream(new ByteArrayInputStream(sigData));
                ois.read(inputSig, 0, sig.length);
                if(!(new String(sig)).equals(new String(inputSig)))
                {
                    throw new OpenStegoException(NAMESPACE, DWTXieErrors.ERR_SIG_NOT_VALID, null);
                }

                watermarkLength = ois.readInt();
                embeddingStrength = ois.readDouble();
                waveletFilterMethod = ois.readInt();
                filterID = ois.readInt();
                embeddingLevel = ois.readInt();

                watermark = new byte[watermarkLength];
                ois.read(watermark);
            }
            catch(IOException ioEx)
            {
                throw new OpenStegoException(ioEx);
            }
        }

        /**
         * Get the signature data generated
         * @return Signature data
         * @throws net.sourceforge.openstego.OpenStegoException
         */
        public byte[] getSigData() throws OpenStegoException
        {
            ByteArrayOutputStream baos = null;
            ObjectOutputStream oos = null;

            try
            {
                baos = new ByteArrayOutputStream();
                oos = new ObjectOutputStream(baos);
                oos.write(sig);
                oos.writeInt(watermarkLength);
                oos.writeDouble(embeddingStrength);
                oos.writeInt(waveletFilterMethod);
                oos.writeInt(filterID);
                oos.writeInt(embeddingLevel);
                oos.write(watermark);
                oos.flush();
                oos.close();

                return baos.toByteArray();
            }
            catch(IOException ioEx)
            {
                throw new OpenStegoException(ioEx);
            }
        }

        /**
         * Method to replace the watermark data
         * @param watermark Watermark data
         */
        public void setWatermark(byte[] watermark)
        {
            this.watermark = watermark;
            this.watermarkLength = watermark.length;
        }
    }

    private class Pixel
    {
        int pos = 0;
        double value = 0.0;

        public Pixel(int pos, double value)
        {
            this.pos = pos;
            this.value = value;
        }
    }
}
