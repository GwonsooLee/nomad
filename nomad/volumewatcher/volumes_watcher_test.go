package volumewatcher

import (
	"context"
	"testing"
	"time"

	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/nomad/helper/testlog"
	"github.com/hashicorp/nomad/nomad/mock"
	"github.com/hashicorp/nomad/nomad/state"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/stretchr/testify/require"
)

// TestVolumeWatch_EnableDisable tests the watcher registration logic that needs
// to happen during leader step-up/step-down
func TestVolumeWatch_EnableDisable(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	srv := &MockRPCServer{}
	srv.state = state.TestStateStore(t)
	index := uint64(100)

	watcher := NewVolumesWatcher(testlog.HCLogger(t),
		srv, srv,
		LimitStateQueriesPerSecond,
		CrossVolumeUpdateBatchDuration)

	watcher.SetEnabled(true, srv.State())

	plugin := mock.CSIPlugin()
	node := testNode(nil, plugin, srv.State())
	alloc := mock.Alloc()
	alloc.ClientStatus = structs.AllocClientStatusComplete
	vol := testVolume(nil, plugin, alloc, node.ID)

	index++
	err := srv.State().CSIVolumeRegister(index, []*structs.CSIVolume{vol})
	require.NoError(err)

	claim := &structs.CSIVolumeClaimRequest{VolumeID: vol.ID}
	claim.Namespace = vol.Namespace

	_, err = watcher.Reap(claim)
	require.NoError(err)
	require.Equal(1, len(watcher.watchers))

	watcher.SetEnabled(false, srv.State())
	require.Equal(0, len(watcher.watchers))
}

// TestVolumeWatch_Checkpoint tests the checkpointing of progress across
// leader leader step-up/step-down
func TestVolumeWatch_Checkpoint(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	srv := &MockRPCServer{}
	srv.state = state.TestStateStore(t)
	index := uint64(100)

	watcher := NewVolumesWatcher(testlog.HCLogger(t),
		srv, srv,
		LimitStateQueriesPerSecond,
		CrossVolumeUpdateBatchDuration)

	plugin := mock.CSIPlugin()
	node := testNode(nil, plugin, srv.State())
	alloc := mock.Alloc()
	alloc.ClientStatus = structs.AllocClientStatusComplete
	vol := testVolume(nil, plugin, alloc, node.ID)

	watcher.SetEnabled(true, srv.State())

	index++
	err := srv.State().CSIVolumeRegister(index, []*structs.CSIVolume{vol})
	require.NoError(err)

	// we should get or start up a watcher when we get an update for
	// the volume from the state store
	require.Eventually(func() bool {
		return 1 == len(watcher.watchers)
	}, time.Second, 10*time.Millisecond)

	// step-down (this is sync, but step-up is async)
	watcher.SetEnabled(false, srv.State())
	require.Equal(0, len(watcher.watchers))

	// step-up again
	watcher.SetEnabled(true, srv.State())
	require.Eventually(func() bool {
		return 1 == len(watcher.watchers)
	}, time.Second, 10*time.Millisecond)

	require.True(watcher.watchers[vol.ID+vol.Namespace].isRunning())
}

// TestVolumeWatch_StartStop tests the start and stop of the watcher when
// it receives notifcations and has completed its work
func TestVolumeWatch_StartStop(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	ctx, exitFn := context.WithCancel(context.Background())
	defer exitFn()

	srv := &MockStatefulRPCServer{}
	srv.state = state.TestStateStore(t)
	index := uint64(100)
	srv.volumeUpdateBatcher = NewVolumeUpdateBatcher(CrossVolumeUpdateBatchDuration, srv, ctx)

	watcher := NewVolumesWatcher(testlog.HCLogger(t),
		srv, srv,
		LimitStateQueriesPerSecond,
		CrossVolumeUpdateBatchDuration)

	watcher.SetEnabled(true, srv.State())
	require.Equal(0, len(watcher.watchers))

	plugin := mock.CSIPlugin()
	node := testNode(nil, plugin, srv.State())
	alloc := mock.Alloc()
	alloc.ClientStatus = structs.AllocClientStatusRunning
	index++
	err := srv.State().UpsertAllocs(index, []*structs.Allocation{alloc})
	require.NoError(err)

	// register a volume
	vol := testVolume(nil, plugin, alloc, node.ID)
	index++
	err = srv.State().CSIVolumeRegister(index, []*structs.CSIVolume{vol})
	require.NoError(err)

	// assert we get a running watcher
	require.Eventually(func() bool {
		return 1 == len(watcher.watchers)
	}, time.Second, 10*time.Millisecond)
	require.True(watcher.watchers[vol.ID+vol.Namespace].isRunning())

	// reap the volume and assert nothing has happened
	claim := &structs.CSIVolumeClaimRequest{
		VolumeID:     vol.ID,
		AllocationID: alloc.ID,
		NodeID:       node.ID,
	}
	claim.Namespace = vol.Namespace
	watcher.Reap(claim)
	require.True(watcher.watchers[vol.ID+vol.Namespace].isRunning())

	// alloc becomes terminal
	alloc.ClientStatus = structs.AllocClientStatusComplete
	index++
	err = srv.State().UpsertAllocs(index, []*structs.Allocation{alloc})
	require.NoError(err)
	index++
	err = srv.State().CSIVolumeClaim(index, vol.Namespace, vol.ID, claim.ToClaim())
	require.NoError(err)

	// claim has been released and watcher stops
	require.Eventually(func() bool {
		ws := memdb.NewWatchSet()
		vol, _ := srv.State().CSIVolumeByID(ws, vol.Namespace, vol.ID)
		return len(vol.ReadAllocs) == 0 && len(vol.PastClaims) == 0
	}, time.Second*2, 10*time.Millisecond)

	require.Equal(1, srv.countCSINodeDetachVolume, "node detach RPC count")
	require.Equal(1, srv.countCSIControllerDetachVolume, "controller detach RPC count")
	require.Equal(2, srv.countUpsertVolumeClaims, "upsert claims count")

	require.Eventually(func() bool {
		return !watcher.watchers[vol.ID+vol.Namespace].isRunning()
	}, time.Second*1, 10*time.Millisecond)

	// the watcher will have incremented the index so we need to make sure
	// our inserts will trigger new events
	index, _ = srv.State().LatestIndex()

	// create a new claim
	alloc2 := mock.Alloc()
	alloc2.ClientStatus = structs.AllocClientStatusRunning
	index++
	err = srv.State().UpsertAllocs(index, []*structs.Allocation{alloc2})
	require.NoError(err)
	claim2 := &structs.CSIVolumeClaimRequest{
		VolumeID:     vol.ID,
		AllocationID: alloc2.ID,
		NodeID:       node.ID,
	}
	claim.Namespace = vol.Namespace
	index++
	err = srv.State().CSIVolumeClaim(index, vol.Namespace, vol.ID, claim2.ToClaim())
	require.NoError(err)

	// a stopped watcher should restore itself on notification
	require.Eventually(func() bool {
		return watcher.watchers[vol.ID+vol.Namespace].isRunning()
	}, time.Second*1, 10*time.Millisecond)
}

// TestVolumeWatch_RegisterDeregister tests the start and stop of
// watchers around registration
func TestVolumeWatch_RegisterDeregister(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	ctx, exitFn := context.WithCancel(context.Background())
	defer exitFn()

	srv := &MockStatefulRPCServer{}
	srv.state = state.TestStateStore(t)
	srv.volumeUpdateBatcher = NewVolumeUpdateBatcher(CrossVolumeUpdateBatchDuration, srv, ctx)

	index := uint64(100)

	watcher := NewVolumesWatcher(testlog.HCLogger(t),
		srv, srv,
		LimitStateQueriesPerSecond,
		CrossVolumeUpdateBatchDuration)

	watcher.SetEnabled(true, srv.State())
	require.Equal(0, len(watcher.watchers))

	plugin := mock.CSIPlugin()
	node := testNode(nil, plugin, srv.State())
	alloc := mock.Alloc()
	alloc.ClientStatus = structs.AllocClientStatusComplete

	// unregistered volumes should never start watchers
	volBad := testVolume(nil, plugin, alloc, node.ID)
	claim := &structs.CSIVolumeClaimRequest{VolumeID: volBad.ID}
	claim.Namespace = volBad.Namespace
	watcher.Reap(claim)
	require.Equal(0, len(watcher.watchers))

	// register a volume
	vol := testVolume(nil, plugin, alloc, node.ID)
	index++
	err := srv.State().CSIVolumeRegister(index, []*structs.CSIVolume{vol})
	require.NoError(err)

	require.Eventually(func() bool {
		return 1 == len(watcher.watchers)
	}, time.Second, 10*time.Millisecond)

	// reap the volume and assert we've cleaned up
	w := watcher.watchers[vol.ID+vol.Namespace]
	w.Notify(vol)

	require.Eventually(func() bool {
		ws := memdb.NewWatchSet()
		vol, _ := srv.State().CSIVolumeByID(ws, vol.Namespace, vol.ID)
		return len(vol.ReadAllocs) == 0 && len(vol.PastClaims) == 0
	}, time.Second*2, 10*time.Millisecond)

	require.Eventually(func() bool {
		return !watcher.watchers[vol.ID+vol.Namespace].isRunning()
	}, time.Second*1, 10*time.Millisecond)

	require.Equal(1, srv.countCSINodeDetachVolume, "node detach RPC count")
	require.Equal(1, srv.countCSIControllerDetachVolume, "controller detach RPC count")
	require.Equal(2, srv.countUpsertVolumeClaims, "upsert claims count")

	// deregister the volume
	err = srv.State().CSIVolumeDeregister(index, vol.Namespace, []string{vol.ID})
	require.NoError(err)

	// reaping a deregistered volume doesn't result in a new watcher
	// or restarting of the existing watcher
	claim = &structs.CSIVolumeClaimRequest{VolumeID: vol.ID}
	claim.Namespace = vol.Namespace
	watcher.Reap(claim)
	require.Equal(1, len(watcher.watchers))
	require.False(watcher.watchers[vol.ID+vol.Namespace].isRunning())
}
