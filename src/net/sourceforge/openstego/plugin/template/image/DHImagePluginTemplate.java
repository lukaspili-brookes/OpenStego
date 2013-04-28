/*
 * Steganography utility to hide messages into cover files
 * Author: Samir Vaidya (mailto:syvaidya@gmail.com)
 * Copyright (c) 2007-2008 Samir Vaidya
 */

package net.sourceforge.openstego.plugin.template.image;

import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.imageio.ImageIO;

import net.sourceforge.openstego.DataHidingPlugin;
import net.sourceforge.openstego.OpenStegoConfig;
import net.sourceforge.openstego.OpenStegoException;
import net.sourceforge.openstego.ui.OpenStegoUI;
import net.sourceforge.openstego.ui.PluginEmbedOptionsUI;
import net.sourceforge.openstego.util.CmdLineOptions;
import net.sourceforge.openstego.util.ImageUtil;

/**
 * Template plugin for OpenStego which implements image based steganography for data hiding
 */
public abstract class DHImagePluginTemplate extends DataHidingPlugin
{
    /**
     * Static list of supported read formats
     */
    protected static List readFormats = null;

    /**
     * Static list of supported write formats
     */
    protected static List writeFormats = null;

    /**
     * Method to get difference between original cover file and the stegged file
     * @param stegoData Stego data containing the embedded data
     * @param stegoFileName Name of the stego file
     * @param coverData Original cover data
     * @param coverFileName Name of the cover file
     * @param diffFileName Name of the output difference file
     * @return Difference data
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public final byte[] getDiff(byte[] stegoData, String stegoFileName, byte[] coverData, String coverFileName,
            String diffFileName) throws OpenStegoException
    {
        BufferedImage stegoImage = null;
        BufferedImage coverImage = null;
        BufferedImage diffImage = null;

        stegoImage = ImageUtil.byteArrayToImage(stegoData, stegoFileName);
        coverImage = ImageUtil.byteArrayToImage(coverData, coverFileName);
        diffImage = ImageUtil.getDiffImage(stegoImage, coverImage);

        return ImageUtil.imageToByteArray(diffImage, diffFileName, this);
    }

    /**
     * Method to get the list of supported file extensions for reading
     * @return List of supported file extensions for reading
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public List getReadableFileExtensions() throws OpenStegoException
    {
        if(readFormats != null)
        {
            return readFormats;
        }

        String format = null;
        String[] formats = null;
        readFormats = new ArrayList();

        formats = ImageIO.getReaderFormatNames();
        for(int i = 0; i < formats.length; i++)
        {
            format = formats[i].toLowerCase();
            if(format.indexOf("jpeg") >= 0 && format.indexOf("2000") >= 0)
            {
                format = "jp2";
            }
            if(!readFormats.contains(format))
            {
                readFormats.add(format);
            }
        }

        Collections.sort(readFormats);
        return readFormats;
    }

    /**
     * Method to get the list of supported file extensions for writing
     * @return List of supported file extensions for writing
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public List getWritableFileExtensions() throws OpenStegoException
    {
        if(writeFormats != null)
        {
            return writeFormats;
        }

        String format = null;
        String[] formats = null;
        writeFormats = new ArrayList();

        formats = ImageIO.getWriterFormatNames();
        for(int i = 0; i < formats.length; i++)
        {
            format = formats[i].toLowerCase();
            if(format.indexOf("jpeg") >= 0 && format.indexOf("2000") >= 0)
            {
                format = "jp2";
            }
            if(!writeFormats.contains(format))
            {
                writeFormats.add(format);
            }
        }

        Collections.sort(writeFormats);
        return writeFormats;
    }

    /**
     * Method to get the UI object specific to this plugin, which will be embedded inside the main OpenStego GUI
     * 
     * @param stegoUI Reference to the parent OpenStegoUI object
     * @return UI object specific to this plugin
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public PluginEmbedOptionsUI getEmbedOptionsUI(OpenStegoUI stegoUI) throws OpenStegoException
    {
        return null;
    }

    /**
     * Method to populate the standard command-line options used by this plugin
     * 
     * @param options Existing command-line options. Plugin-specific options will get added to this list
     * @throws net.sourceforge.openstego.OpenStegoException
     */
    public void populateStdCmdLineOptions(CmdLineOptions options) throws OpenStegoException
    {
    }

    /**
     * Method to get the configuration class specific to this plugin
     * @return Configuration class specific to this plugin
     */
    public Class getConfigClass()
    {
        return OpenStegoConfig.class;
    }
}
