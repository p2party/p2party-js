// MessageType enum
export enum MessageType {
  Text = 1,
  ImagePNG = 2,
  ImageJPEG = 3,
  ImageJPG = 4,
  ImageGIF = 5,
  ImageBMP = 6,
  ImageTIFF = 7,
  ImageSVG = 8,
  ImageWEBP = 9,
  ImageHEIC = 10,
  DocumentPDF = 11,
  DocumentDOC = 12,
  DocumentDOCX = 13,
  DocumentXLS = 14,
  DocumentXLSX = 15,
  DocumentPPT = 16,
  DocumentPPTX = 17,
  DocumentTXT = 18,
  DocumentRTF = 19,
  DocumentODT = 20,
  AudioMP3 = 21,
  AudioWAV = 22,
  AudioAAC = 23,
  AudioFLAC = 24,
  AudioOGG = 25,
  AudioM4A = 26,
  VideoMP4 = 27,
  VideoAVI = 28,
  VideoMKV = 29,
  VideoMOV = 30,
  VideoWMV = 31,
  VideoFLV = 32,
  VideoWEBM = 33,
  CompressedZIP = 34,
  CompressedRAR = 35,
  Compressed7Z = 36,
  CompressedTAR = 37,
  CompressedGZ = 38,
  CodeHTML = 39,
  CodeCSS = 40,
  CodeJS = 41,
  CodeJSX = 42,
  CodeTS = 43,
  CodeTSX = 44,
  CodeJSON = 45,
  CodeXML = 46,
  CodePY = 47,
  CodeJAVA = 48,
  CodeC = 49,
  CodeCPP = 50,
  CodeCS = 51,
  CodeRB = 52,
  CodePHP = 53,
  CodeSQL = 54,
  EbookEPUB = 55,
  EbookMOBI = 56,
  EbookAZW = 57,
  FontTTF = 58,
  FontOTF = 59,
  ImageICO = 60,
  ExecutableEXE = 61,
  ExecutableDMG = 62,
  ExecutableAPK = 63,
}

export const getMessageType = (data: string | File): MessageType => {
  if (typeof data === "string") return MessageType.Text;

  const extension = data.name.split(".").pop()?.toLowerCase() || "";
  const extensionToMessageType: { [key: string]: MessageType } = {
    png: MessageType.ImagePNG,
    jpeg: MessageType.ImageJPEG,
    jpg: MessageType.ImageJPG,
    gif: MessageType.ImageGIF,
    bmp: MessageType.ImageBMP,
    tiff: MessageType.ImageTIFF,
    svg: MessageType.ImageSVG,
    webp: MessageType.ImageWEBP,
    heic: MessageType.ImageHEIC,
    pdf: MessageType.DocumentPDF,
    doc: MessageType.DocumentDOC,
    docx: MessageType.DocumentDOCX,
    xls: MessageType.DocumentXLS,
    xlsx: MessageType.DocumentXLSX,
    ppt: MessageType.DocumentPPT,
    pptx: MessageType.DocumentPPTX,
    txt: MessageType.DocumentTXT,
    rtf: MessageType.DocumentRTF,
    odt: MessageType.DocumentODT,
    mp3: MessageType.AudioMP3,
    wav: MessageType.AudioWAV,
    aac: MessageType.AudioAAC,
    flac: MessageType.AudioFLAC,
    ogg: MessageType.AudioOGG,
    m4a: MessageType.AudioM4A,
    mp4: MessageType.VideoMP4,
    avi: MessageType.VideoAVI,
    mkv: MessageType.VideoMKV,
    mov: MessageType.VideoMOV,
    wmv: MessageType.VideoWMV,
    flv: MessageType.VideoFLV,
    webm: MessageType.VideoWEBM,
    zip: MessageType.CompressedZIP,
    rar: MessageType.CompressedRAR,
    "7z": MessageType.Compressed7Z,
    tar: MessageType.CompressedTAR,
    gz: MessageType.CompressedGZ,
    html: MessageType.CodeHTML,
    css: MessageType.CodeCSS,
    js: MessageType.CodeJS,
    ts: MessageType.CodeTS,
    jsx: MessageType.CodeJSX,
    tsx: MessageType.CodeTSX,
    json: MessageType.CodeJSON,
    xml: MessageType.CodeXML,
    py: MessageType.CodePY,
    java: MessageType.CodeJAVA,
    c: MessageType.CodeC,
    cpp: MessageType.CodeCPP,
    cs: MessageType.CodeCS,
    rb: MessageType.CodeRB,
    php: MessageType.CodePHP,
    sql: MessageType.CodeSQL,
    epub: MessageType.EbookEPUB,
    mobi: MessageType.EbookMOBI,
    azw: MessageType.EbookAZW,
    ttf: MessageType.FontTTF,
    otf: MessageType.FontOTF,
    ico: MessageType.ImageICO,
    exe: MessageType.ExecutableEXE,
    dmg: MessageType.ExecutableDMG,
    apk: MessageType.ExecutableAPK,
  };

  return extensionToMessageType[extension] || MessageType.Text;
};

export const getFileExtension = (messageType: MessageType): string => {
  switch (messageType) {
    case MessageType.ImagePNG:
      return "png";
    case MessageType.ImageJPEG:
      return "jpeg";
    case MessageType.ImageJPG:
      return "jpg";
    case MessageType.ImageGIF:
      return "gif";
    case MessageType.ImageBMP:
      return "bmp";
    case MessageType.ImageTIFF:
      return "tiff";
    case MessageType.ImageSVG:
      return "svg";
    case MessageType.ImageWEBP:
      return "webp";
    case MessageType.ImageHEIC:
      return "heic";
    case MessageType.DocumentPDF:
      return "pdf";
    case MessageType.DocumentDOC:
      return "doc";
    case MessageType.DocumentDOCX:
      return "docx";
    case MessageType.DocumentXLS:
      return "xls";
    case MessageType.DocumentXLSX:
      return "xlsx";
    case MessageType.DocumentPPT:
      return "ppt";
    case MessageType.DocumentPPTX:
      return "pptx";
    case MessageType.DocumentTXT:
      return "txt";
    case MessageType.DocumentRTF:
      return "rtf";
    case MessageType.DocumentODT:
      return "odt";
    case MessageType.AudioMP3:
      return "mp3";
    case MessageType.AudioWAV:
      return "wav";
    case MessageType.AudioAAC:
      return "aac";
    case MessageType.AudioFLAC:
      return "flac";
    case MessageType.AudioOGG:
      return "ogg";
    case MessageType.AudioM4A:
      return "m4a";
    case MessageType.VideoMP4:
      return "mp4";
    case MessageType.VideoAVI:
      return "avi";
    case MessageType.VideoMKV:
      return "mkv";
    case MessageType.VideoMOV:
      return "mov";
    case MessageType.VideoWMV:
      return "wmv";
    case MessageType.VideoFLV:
      return "flv";
    case MessageType.VideoWEBM:
      return "webm";
    case MessageType.CompressedZIP:
      return "zip";
    case MessageType.CompressedRAR:
      return "rar";
    case MessageType.Compressed7Z:
      return "7z";
    case MessageType.CompressedTAR:
      return "tar";
    case MessageType.CompressedGZ:
      return "gz";
    case MessageType.CodeHTML:
      return "html";
    case MessageType.CodeCSS:
      return "css";
    case MessageType.CodeJS:
      return "js";
    case MessageType.CodeTS:
      return "ts";
    case MessageType.CodeJSX:
      return "jsx";
    case MessageType.CodeTSX:
      return "tsx";
    case MessageType.CodeJSON:
      return "json";
    case MessageType.CodeXML:
      return "xml";
    case MessageType.CodePY:
      return "py";
    case MessageType.CodeJAVA:
      return "java";
    case MessageType.CodeC:
      return "c";
    case MessageType.CodeCPP:
      return "cpp";
    case MessageType.CodeCS:
      return "cs";
    case MessageType.CodeRB:
      return "rb";
    case MessageType.CodePHP:
      return "php";
    case MessageType.CodeSQL:
      return "sql";
    case MessageType.EbookEPUB:
      return "epub";
    case MessageType.EbookMOBI:
      return "mobi";
    case MessageType.EbookAZW:
      return "azw";
    case MessageType.FontTTF:
      return "ttf";
    case MessageType.FontOTF:
      return "otf";
    case MessageType.ImageICO:
      return "ico";
    case MessageType.ExecutableEXE:
      return "exe";
    case MessageType.ExecutableDMG:
      return "dmg";
    case MessageType.ExecutableAPK:
      return "apk";
    default:
      return "";
  }
};
