package tomikaa.greeremote.device;

import android.os.AsyncTask;
import android.util.Log;

import com.google.gson.Gson;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;

import tomikaa.greeremote.device.packets.BindResponsePacket;
import tomikaa.greeremote.device.packets.DeviceDetailsPacket;
import tomikaa.greeremote.device.packets.DeviceResponsePacket;

/**
 * Created by tomikaa on 2017. 10. 26..
 */

public class AsyncBinder extends AsyncTask<DeviceDetailsPacket[], Void, BindResponsePacket[]> {
    private static final String LOG_TAG = "AsyncBinder";
    private AsyncOperationFinishedListener mFinishedListener;
    private final DatagramSocket mSocket;

    public AsyncBinder(DatagramSocket socket) {
        mSocket = socket;
    }

    public void setFinishedListener(AsyncOperationFinishedListener listener) {
        mFinishedListener = listener;
    }

    /**
     * Override this method to perform a computation on a background thread. The
     * specified parameters are the parameters passed to {@link #execute}
     * by the caller of this task.
     * <p>
     * This method can call {@link #publishProgress} to publish updates
     * on the UI thread.
     *
     * @param params The parameters of the task.
     * @return A result, defined by the subclass of this task.
     * @see #onPreExecute()
     * @see #onPostExecute
     * @see #publishProgress
     */
    @Override
    protected BindResponsePacket[] doInBackground(DeviceDetailsPacket[]... params) {
        if (params.length == 0)
            return new BindResponsePacket[0];

        ArrayList<DeviceResponsePacket> responses = new ArrayList<>();
        DeviceDetailsPacket[] devices = params[0];

        if (devices == null || devices.length == 0)
            return new BindResponsePacket[0];

        try {
            Log.d(LOG_TAG, "sending bind packet(s)");

            for (DeviceDetailsPacket device: devices) {
                String scanPacketContent = ProtocolUtils.createBindPacket(device.cid);
                DatagramPacket scanPacket = new DatagramPacket(
                        scanPacketContent.getBytes(),
                        scanPacketContent.length(),
                        InetAddress.getByName("192.168.1.255"),
                        7000);
                mSocket.send(scanPacket);
            }

            Log.d(LOG_TAG, "setting receive timeout");
            mSocket.setSoTimeout(5000);

            while (true) {

                Log.d(LOG_TAG, "waiting for response");
                byte[] buf = new byte[65536];
                DatagramPacket packet = new DatagramPacket(buf, 65536);
                mSocket.receive(packet);

                Log.d(LOG_TAG, "response received");
                InetAddress address = packet.getAddress();
                byte[] data = packet.getData();
                String json = new String(data, 0, packet.getLength());
                Log.d(LOG_TAG, String.format("response from %s: %s", address.getHostAddress(), json));

                Gson gson = new Gson();
                responses.add(gson.fromJson(json, DeviceResponsePacket.class));
            }
        } catch (SocketTimeoutException e) {
            Log.d(LOG_TAG, "socket timeout");
        } catch (SocketException e) {
            Log.w(LOG_TAG, "socket error: " + e.getMessage());
            return null;
        } catch (IOException e) {
            Log.w(LOG_TAG, "io error: " + e.getMessage());
            return null;
        }

        Log.d(LOG_TAG, String.format("got %d bind response(s)", responses.size()));

        ArrayList<BindResponsePacket> boundDevices = new ArrayList<>();

        for (DeviceResponsePacket packet: responses) {
            if (packet.pack == null)
                continue;

            String packJson = ProtocolUtils.decryptPack(packet.pack, ProtocolUtils.GENERIC_AES_KEY);
            Log.d(LOG_TAG, "packJson: " + packJson);

            Gson gson = new Gson();
            BindResponsePacket bindResponse = gson.fromJson(packJson, BindResponsePacket.class);
            if ("bindok".equalsIgnoreCase(bindResponse.t))
                boundDevices.add(bindResponse);
        }

        Log.d(LOG_TAG, String.format("bound %d device(s)", boundDevices.size()));
        Log.d(LOG_TAG, "finished");

        return boundDevices.toArray(new BindResponsePacket[0]);
    }

    /**
     * <p>Runs on the UI thread after {@link #doInBackground}. The
     * specified result is the value returned by {@link #doInBackground}.</p>
     * <p>
     * <p>This method won't be invoked if the task was cancelled.</p>
     *
     * @param bindResponsePackets The result of the operation computed by {@link #doInBackground}.
     * @see #onPreExecute
     * @see #doInBackground
     * @see #onCancelled(Object)
     */
    @Override
    protected void onPostExecute(BindResponsePacket[] bindResponsePackets) {
        super.onPostExecute(bindResponsePackets);

        if (mFinishedListener != null)
            mFinishedListener.onFinished();
    }
}
