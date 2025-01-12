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
  Unknown = 64,
}

export enum MessageCategory {
  Text = "Text",
  Image = "Image",
  Document = "Document",
  Audio = "Audio",
  Video = "Video",
  Compressed = "Compressed",
  Code = "Code",
  Ebook = "Ebook",
  Font = "Font",
  Executable = "Executable",
  Unknown = "Unknown",
}

export type KnownMimeType =
  | "text/plain"
  | "image/png"
  | "image/jpeg"
  | "image/gif"
  | "image/bmp"
  | "image/tiff"
  | "image/svg+xml"
  | "image/webp"
  | "image/heic"
  | "image/vnd.microsoft.icon"
  | "application/pdf"
  | "application/msword"
  | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  | "application/vnd.ms-excel"
  | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
  | "application/vnd.ms-powerpoint"
  | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
  | "application/rtf"
  | "application/vnd.oasis.opendocument.text"
  | "audio/mpeg"
  | "audio/wav"
  | "audio/aac"
  | "audio/flac"
  | "audio/ogg"
  | "audio/mp4"
  | "video/mp4"
  | "video/x-msvideo"
  | "video/x-matroska"
  | "video/quicktime"
  | "video/x-ms-wmv"
  | "video/x-flv"
  | "video/webm"
  | "application/zip"
  | "application/vnd.rar"
  | "application/x-7z-compressed"
  | "application/x-tar"
  | "application/gzip"
  | "text/html"
  | "text/css"
  | "application/javascript"
  | "application/typescript"
  | "application/json"
  | "application/xml"
  | "text/x-python"
  | "text/x-java-source"
  | "text/x-c"
  | "text/x-c++"
  | "text/x-ruby"
  | "application/x-httpd-php"
  | "application/sql"
  | "application/epub+zip"
  | "application/x-mobipocket-ebook"
  | "application/vnd.amazon.ebook"
  | "font/ttf"
  | "font/otf"
  | "application/vnd.microsoft.portable-executable"
  | "application/x-apple-diskimage"
  | "application/vnd.android.package-archive";

export type MimeType = KnownMimeType | "application/octet-stream";

export type KnownFileExtension =
  | "png"
  | "jpeg"
  | "jpg"
  | "gif"
  | "bmp"
  | "tiff"
  | "svg"
  | "webp"
  | "heic"
  | "ico"
  | "pdf"
  | "doc"
  | "docx"
  | "xls"
  | "xlsx"
  | "ppt"
  | "pptx"
  | "txt"
  | "rtf"
  | "odt"
  | "mp3"
  | "wav"
  | "aac"
  | "flac"
  | "ogg"
  | "m4a"
  | "mp4"
  | "avi"
  | "mkv"
  | "mov"
  | "wmv"
  | "flv"
  | "webm"
  | "zip"
  | "rar"
  | "7z"
  | "tar"
  | "gz"
  | "html"
  | "css"
  | "js"
  | "ts"
  | "jsx"
  | "tsx"
  | "json"
  | "xml"
  | "py"
  | "java"
  | "c"
  | "cpp"
  | "cs"
  | "rb"
  | "php"
  | "sql"
  | "epub"
  | "mobi"
  | "azw"
  | "ttf"
  | "otf"
  | "exe"
  | "dmg"
  | "apk";

export type FileExtension = KnownFileExtension | "";

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

  return extensionToMessageType[extension] || MessageType.Unknown;
};

export const getFileExtension = (messageType: MessageType): FileExtension => {
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

export const getMimeType = (messageType: MessageType): MimeType => {
  switch (messageType) {
    case MessageType.Text:
      return "text/plain";
    case MessageType.ImagePNG:
      return "image/png";
    case MessageType.ImageJPEG:
    case MessageType.ImageJPG:
      return "image/jpeg";
    case MessageType.ImageGIF:
      return "image/gif";
    case MessageType.ImageBMP:
      return "image/bmp";
    case MessageType.ImageTIFF:
      return "image/tiff";
    case MessageType.ImageSVG:
      return "image/svg+xml";
    case MessageType.ImageWEBP:
      return "image/webp";
    case MessageType.ImageHEIC:
      return "image/heic";
    case MessageType.ImageICO:
      return "image/vnd.microsoft.icon";
    case MessageType.DocumentPDF:
      return "application/pdf";
    case MessageType.DocumentDOC:
      return "application/msword";
    case MessageType.DocumentDOCX:
      return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case MessageType.DocumentXLS:
      return "application/vnd.ms-excel";
    case MessageType.DocumentXLSX:
      return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case MessageType.DocumentPPT:
      return "application/vnd.ms-powerpoint";
    case MessageType.DocumentPPTX:
      return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    case MessageType.DocumentTXT:
      return "text/plain";
    case MessageType.DocumentRTF:
      return "application/rtf";
    case MessageType.DocumentODT:
      return "application/vnd.oasis.opendocument.text";
    case MessageType.AudioMP3:
      return "audio/mpeg";
    case MessageType.AudioWAV:
      return "audio/wav";
    case MessageType.AudioAAC:
      return "audio/aac";
    case MessageType.AudioFLAC:
      return "audio/flac";
    case MessageType.AudioOGG:
      return "audio/ogg";
    case MessageType.AudioM4A:
      return "audio/mp4"; // M4A is usually audio in MP4 container
    case MessageType.VideoMP4:
      return "video/mp4";
    case MessageType.VideoAVI:
      return "video/x-msvideo";
    case MessageType.VideoMKV:
      return "video/x-matroska";
    case MessageType.VideoMOV:
      return "video/quicktime";
    case MessageType.VideoWMV:
      return "video/x-ms-wmv";
    case MessageType.VideoFLV:
      return "video/x-flv";
    case MessageType.VideoWEBM:
      return "video/webm";
    case MessageType.CompressedZIP:
      return "application/zip";
    case MessageType.CompressedRAR:
      return "application/vnd.rar";
    case MessageType.Compressed7Z:
      return "application/x-7z-compressed";
    case MessageType.CompressedTAR:
      return "application/x-tar";
    case MessageType.CompressedGZ:
      return "application/gzip";
    case MessageType.CodeHTML:
      return "text/html";
    case MessageType.CodeCSS:
      return "text/css";
    case MessageType.CodeJS:
    case MessageType.CodeJSX:
      return "application/javascript";
    case MessageType.CodeTS:
    case MessageType.CodeTSX:
      return "application/typescript";
    case MessageType.CodeJSON:
      return "application/json";
    case MessageType.CodeXML:
      return "application/xml";
    case MessageType.CodePY:
      return "text/x-python";
    case MessageType.CodeJAVA:
      return "text/x-java-source";
    case MessageType.CodeC:
      return "text/x-c";
    case MessageType.CodeCPP:
      return "text/x-c++";
    case MessageType.CodeCS:
      return "text/plain"; // No specific MIME type for C#
    case MessageType.CodeRB:
      return "text/x-ruby";
    case MessageType.CodePHP:
      return "application/x-httpd-php";
    case MessageType.CodeSQL:
      return "application/sql";
    case MessageType.EbookEPUB:
      return "application/epub+zip";
    case MessageType.EbookMOBI:
      return "application/x-mobipocket-ebook";
    case MessageType.EbookAZW:
      return "application/vnd.amazon.ebook";
    case MessageType.FontTTF:
      return "font/ttf";
    case MessageType.FontOTF:
      return "font/otf";
    case MessageType.ExecutableEXE:
      return "application/vnd.microsoft.portable-executable";
    case MessageType.ExecutableDMG:
      return "application/x-apple-diskimage";
    case MessageType.ExecutableAPK:
      return "application/vnd.android.package-archive";
    default:
      return "application/octet-stream";
  }
};

export const getMessageCategory = (
  messageType: MessageType,
): MessageCategory => {
  switch (messageType) {
    case MessageType.Text:
      return MessageCategory.Text;

    case MessageType.ImagePNG:
    case MessageType.ImageJPEG:
    case MessageType.ImageJPG:
    case MessageType.ImageGIF:
    case MessageType.ImageBMP:
    case MessageType.ImageTIFF:
    case MessageType.ImageSVG:
    case MessageType.ImageWEBP:
    case MessageType.ImageHEIC:
    case MessageType.ImageICO:
      return MessageCategory.Image;

    case MessageType.DocumentPDF:
    case MessageType.DocumentDOC:
    case MessageType.DocumentDOCX:
    case MessageType.DocumentXLS:
    case MessageType.DocumentXLSX:
    case MessageType.DocumentPPT:
    case MessageType.DocumentPPTX:
    case MessageType.DocumentTXT:
    case MessageType.DocumentRTF:
    case MessageType.DocumentODT:
      return MessageCategory.Document;

    case MessageType.AudioMP3:
    case MessageType.AudioWAV:
    case MessageType.AudioAAC:
    case MessageType.AudioFLAC:
    case MessageType.AudioOGG:
    case MessageType.AudioM4A:
      return MessageCategory.Audio;

    case MessageType.VideoMP4:
    case MessageType.VideoAVI:
    case MessageType.VideoMKV:
    case MessageType.VideoMOV:
    case MessageType.VideoWMV:
    case MessageType.VideoFLV:
    case MessageType.VideoWEBM:
      return MessageCategory.Video;

    case MessageType.CompressedZIP:
    case MessageType.CompressedRAR:
    case MessageType.Compressed7Z:
    case MessageType.CompressedTAR:
    case MessageType.CompressedGZ:
      return MessageCategory.Compressed;

    case MessageType.CodeHTML:
    case MessageType.CodeCSS:
    case MessageType.CodeJS:
    case MessageType.CodeJSX:
    case MessageType.CodeTS:
    case MessageType.CodeTSX:
    case MessageType.CodeJSON:
    case MessageType.CodeXML:
    case MessageType.CodePY:
    case MessageType.CodeJAVA:
    case MessageType.CodeC:
    case MessageType.CodeCPP:
    case MessageType.CodeCS:
    case MessageType.CodeRB:
    case MessageType.CodePHP:
    case MessageType.CodeSQL:
      return MessageCategory.Code;

    case MessageType.EbookEPUB:
    case MessageType.EbookMOBI:
    case MessageType.EbookAZW:
      return MessageCategory.Ebook;

    case MessageType.FontTTF:
    case MessageType.FontOTF:
      return MessageCategory.Font;

    case MessageType.ExecutableEXE:
    case MessageType.ExecutableDMG:
    case MessageType.ExecutableAPK:
      return MessageCategory.Executable;

    default:
      return MessageCategory.Unknown;
  }
};
