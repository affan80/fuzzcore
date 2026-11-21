import {Platform} from 'react-native';
import {File,Paths} from 'expo-file-system';
import * as Sharing from 'expo-sharing';

export async function exportReport(scanId:string, format:'json'|'html', content:string) {
  if (!/^[a-zA-Z0-9-]{1,64}$/.test(scanId)) throw new Error('Invalid report identifier.');
  const name=`fuzzcore-${scanId}.${format}`;
  const mime=format==='json'?'application/json':'text/html';
  if (Platform.OS==='web') {
    const url=URL.createObjectURL(new Blob([content],{type:mime}));
    const link=document.createElement('a');link.href=url;link.download=name;link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
    return;
  }
  if (!await Sharing.isAvailableAsync()) throw new Error('File sharing is unavailable on this device.');
  const file=new File(Paths.cache,`${Date.now()}-${name}`);
  try {
    file.create();await file.write(content);
    await Sharing.shareAsync(file.uri,{mimeType:mime,dialogTitle:'Export FuzzCore lab report'});
  } finally {if(file.exists)file.delete();}
}
