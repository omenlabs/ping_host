/*
 * IRIX 6.2 Ping Host program
 * Plays a sound out the speaker when an ICMP echo request is received.
 *
 * https://github.com/omenlabs/ping_host
 *
 * Copyright (c) 2020, John Hickey All rights reserved.
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <bstring.h>
#include <sys/time.h>

#include <dmedia/audio.h>
#include <dmedia/audiofile.h>

#include <pcap.h>

static char sound[] = "/usr/share/data/sounds/soundscheme/soundfiles/08.ting.aifc";

struct sound {
	short *buffer;
	double rate;
	long samples;
	ALport output_port;
};

void openPort(struct sound *snd);

void openSound(struct sound *snd, const char *filename) {
	AFfilehandle afh;
	int res;
	double rate;
	int frames;

	/*
	 * Open File
	 */
	afh = afOpenFile(filename, "r", NULL);
	afSetVirtualByteOrder(afh, AF_DEFAULT_TRACK, AF_BYTEORDER_BIGENDIAN);
	afSetVirtualChannels(afh, AF_DEFAULT_TRACK, 2);
	afSetVirtualSampleFormat(afh, AF_DEFAULT_TRACK, AF_SAMPFMT_TWOSCOMP, 16);

	/*
	 * Sync these with the port
	 */
	if (afGetRate(afh, AF_DEFAULT_TRACK) != 44100.0) {
		printf("Expecting 44.1khz file\n");
		exit(1);
	}

	frames = afGetFrameCount(afh, AF_DEFAULT_TRACK);
	snd->samples = afGetChannels(afh, AF_DEFAULT_TRACK) * frames;

	/*
	 * Read into the buffer
	 */
	snd->buffer = (short *)malloc(frames * afGetVirtualFrameSize(afh, AF_DEFAULT_TRACK, 1));

	res = afReadFrames(afh, AF_DEFAULT_TRACK, snd->buffer, frames);
	openPort(snd);
}

void closeSound(struct sound *snd) {
	ALcloseport(snd->output_port);
	free(snd->buffer);
}

void openPort(struct sound *snd) {
	ALconfig config;
	long buffer[4];
	fd_set out_fds;
	int output_port_fd;

        buffer[0] = AL_CHANNEL_MODE;
        ALgetparams(AL_DEFAULT_DEVICE, buffer, 2);
        printf("Channel mode: %li\n", buffer[1]);

	/* 
	 * Output Configuration
	 */
	buffer[0] = AL_OUTPUT_RATE;
	buffer[1] = 44100;
	ALsetparams(AL_DEFAULT_DEVICE, buffer, 2);

	config = ALnewconfig();
	ALsetwidth(config, AL_SAMPLE_16);
	if (ALsetchannels(config, AL_STEREO)) {
		fprintf(stderr, "Failed to set channels\n");
	}

	ALsetqueuesize(config, snd->samples); /* So we can use select */
	snd->output_port = ALopenport("output", "w", config);
	if (snd->output_port == NULL) {
		fprintf(stderr, "Failed to open audio output port\n");
		exit(-1);
	}

	ALsetfillpoint(snd->output_port, snd->samples - 1); /* Fill point is where select will unblock */
}

void playSound(struct sound *snd, int wait) {
	fd_set out_fds;
	int output_port_fd;
	int r;

	if (wait == 0) {
		if(ALgetfilled(snd->output_port)) {
			printf("Sound already in progress");
			return;
		}
	}

	/*
	 * Setup for select
	 */
	FD_ZERO(&out_fds);
	output_port_fd = ALgetfd(snd->output_port);
	FD_SET(output_port_fd, &out_fds);

	printf("Writing %i\n", snd->samples);
	r = ALwritesamps(snd->output_port, snd->buffer, snd->samples);

	if (wait) {
		select(output_port_fd + 1, (fd_set *)0, &out_fds, (fd_set *)0,
				(struct timeval *)0);
	}
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct sound *snd = (struct sound*) args;
	printf("Ping!\n");
	playSound(snd, 0);
}

int main(int argc, char **argv) {
	struct sound snd;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program bpf;
	char filter_exp[] = "icmp[icmptype] = icmp-echo";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	openSound(&snd, sound);

	/* See https://www.tcpdump.org/pcap.html */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		exit(1);
	}
	printf("Using device: %s\n", dev);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		exit(1);
	}

	handle = pcap_open_live(dev, 128, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(1);
	}

	if (pcap_compile(handle, &bpf, filter_exp, 1, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	
	if (pcap_setfilter(handle, &bpf) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	pcap_loop(handle, 1023, &handle_packet, (u_char *)&snd);

	closeSound(&snd);
}
